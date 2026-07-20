package api

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// ==================== Assistant: Rule Helpers ====================

type GenerateRequest struct {
	Scenario  string `json:"scenario"`  // block_port, allow_ip, allow_ip_port, restrict_port, limit_rate
	Chain     string `json:"chain"`     // INPUT, FORWARD, DOCKER_USER
	Backend   string `json:"backend"`   // all, iptables, nftables, firewalld
	Zone      string `json:"zone"`      // assistant-only firewalld zone
	Family    string `json:"family"`    // ipv4, ipv6, empty for both
	Permanent bool   `json:"permanent"` // assistant-only firewalld --permanent
	Port      string `json:"port"`      // e.g. "8080" or "8000:9000"
	Protocol  string `json:"protocol"`  // tcp, udp, all
	Source    string `json:"source"`    // IP or CIDR
	Interface string `json:"interface"` // eth0, docker0, etc.
	Comment   string `json:"comment"`   // description
}

type InterpretRequest struct {
	Command string `json:"command"` // iptables or nft command to explain
}

type AssistantResponse struct {
	Commands    []CommandVariant `json:"commands,omitempty"`
	Explanation string           `json:"explanation,omitempty"`
	Warnings    []string         `json:"warnings,omitempty"`
	Scenarios   []ScenarioInfo   `json:"scenarios,omitempty"`
	Backend     string           `json:"backend"`
}

type CommandVariant struct {
	Label   string `json:"label"` // "iptables" or "nftables"
	Command string `json:"command"`
	Note    string `json:"note,omitempty"`
}

type ScenarioInfo struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Example     string `json:"example"`
}

var scenarios = []ScenarioInfo{
	{
		ID:          "block_port",
		Title:       "阻止外部访问指定端口",
		Description: "INPUT 用于宿主机服务；Docker 发布端口请选择 DOCKER_USER，程序将按 DNAT 前的宿主机端口生成规则。",
		Example:     "宿主机端口: 8880 → iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8880 -j DROP",
	},
	{
		ID:    "allow_ip",
		Title: "仅允许指定 IP 访问所有端口",
		Description: "先添加 ACCEPT 规则允许特定 IP，再添加 DROP 规则拒绝所有其他来源。" +
			" 注意规则顺序：ACCEPT 必须在 DROP 之前。",
		Example: "来源: 192.168.1.100 → -I INPUT -s 192.168.1.100 -j ACCEPT; -A INPUT -j DROP",
	},
	{
		ID:          "allow_ip_port",
		Title:       "仅允许指定 IP 访问指定端口",
		Description: "只允许特定 IP 段访问端口。宿主机服务选 INPUT；Docker 发布端口选 DOCKER_USER。需要 ACCEPT 在前、DROP 在后。",
		Example:     "Docker 来源: 10.0.0.0/8 宿主机端口: 3306 → DOCKER-USER + --ctorigdstport 3306",
	},
	{
		ID:    "restrict_port",
		Title: "限制端口仅内网访问",
		Description: "阻止来自外网（非内网 IP 段）对指定端口的访问，" +
			" 保留内网访问能力。典型场景：数据库端口只允许内网连接。",
		Example: "内网: 172.16.0.0/12 端口: 5432 → -A INPUT ! -s 172.16.0.0/12 -p tcp --dport 5432 -j DROP",
	},
	{
		ID:    "limit_rate",
		Title: "限制连接速率（防 DDoS）",
		Description: "限制单个 IP 对指定端口的连接速率，超过限制的连接被丢弃。" +
			" 适用于 SSH、Web 服务等需要防止暴力攻击的场景。",
		Example: "端口: 22 → -I INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set; -I INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP",
	},
}

func (h *Handler) GenerateCommand(w http.ResponseWriter, r *http.Request) {
	var req GenerateRequest
	if err := decodeJSONBody(w, r, &req, defaultJSONBodyLimit); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	if req.Scenario == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "scenario is required")
		return
	}
	if req.Chain == "" {
		req.Chain = "INPUT"
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if err := normalizeAndValidateGenerateRequest(&req); err != nil {
		respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	backend := h.executor.BackendName()

	cmds, warnings := buildCommands(req)
	if req.Source != "" && req.Backend == "firewalld" && req.Family == "" {
		warnings = append(warnings, "firewalld rich rule 使用来源地址时建议显式选择 ipv4 或 ipv6 地址族。")
	}

	resp := AssistantResponse{
		Commands: cmds,
		Warnings: warnings,
		Backend:  backend,
	}
	respondOK(w, resp)
}

func (h *Handler) InterpretCommand(w http.ResponseWriter, r *http.Request) {
	var req InterpretRequest
	if err := decodeJSONBody(w, r, &req, defaultJSONBodyLimit); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "command is required")
		return
	}

	explanation, warnings := explainCommand(req.Command)
	resp := AssistantResponse{
		Explanation: explanation,
		Warnings:    warnings,
	}
	respondOK(w, resp)
}

func (h *Handler) ListScenarios(w http.ResponseWriter, r *http.Request) {
	respondOK(w, scenarios)
}

func buildCommands(req GenerateRequest) ([]CommandVariant, []string) {
	var cmds []CommandVariant
	var warnings []string

	chain := commandChain(strings.ToUpper(strings.TrimSpace(req.Chain)))
	proto := strings.ToLower(strings.TrimSpace(req.Protocol))
	port := strings.TrimSpace(req.Port)
	src := strings.TrimSpace(req.Source)
	iface := strings.TrimSpace(req.Interface)
	targetBackend := strings.ToLower(strings.TrimSpace(req.Backend))
	if targetBackend == "" {
		targetBackend = "all"
	}

	switch req.Scenario {
	case "block_port":
		iptCmd := buildIptablesRuleForFamily(req.Family, chain, 1, "DROP", proto, src, "", iptablesPort(port), "", iface, "")
		nftCmd := buildNftablesRule(req.Family, chain, "drop", proto, src, "", nftPort(port), "", iface, "")
		cmds = append(cmds,
			CommandVariant{Label: "iptables", Command: iptCmd, Note: "阻止所有流量访问该端口"},
			CommandVariant{Label: "nftables", Command: nftCmd, Note: "nftables 原生语法"},
			CommandVariant{Label: "firewalld", Command: buildFirewalldRichCommands(req, buildFirewalldRichRule(req, "drop", src != "", `priority="-50"`)), Note: "firewalld rich rule，仅生成命令，不由规则管理页面执行"},
		)

	case "allow_ip":
		iptAccept := buildIptablesRuleForFamily(req.Family, chain, 1, "ACCEPT", "", src, "", "", "", iface, "")
		iptDrop := buildIptablesRuleForFamily(req.Family, chain, 2, "DROP", "", "", "", "", "", iface, "")
		nftAccept := buildNftablesRule(req.Family, chain, "accept", "", src, "", "", "", iface, "")
		nftDrop := buildNftablesRule(req.Family, chain, "drop", "", "", "", "", "", iface, "")
		cmds = append(cmds,
			CommandVariant{Label: "iptables", Command: iptAccept + "\n" + iptDrop,
				Note: "显式插入第 1、2 位：先允许指定 IP，再拒绝其他来源"},
			CommandVariant{Label: "nftables", Command: nftAccept + "\n" + nftDrop,
				Note: "nftables 原生语法，规则评估顺序为线性"},
			CommandVariant{Label: "firewalld", Command: buildFirewalldRichCommands(req,
				buildFirewalldRichRule(req, "accept", true, `priority="-100"`),
				buildFirewalldRichRule(req, "drop", false, `priority="-90"`)), Note: "显式 priority 保证白名单先于兜底拒绝"},
		)
		warnings = append(warnings, "该场景会拒绝所选链中除白名单外的全部流量；远程执行前必须确认当前管理地址已包含在白名单中。")

	case "allow_ip_port":
		iptAccept := buildIptablesRuleForFamily(req.Family, chain, 1, "ACCEPT", proto, src, "", iptablesPort(port), "", iface, "")
		iptDrop := buildIptablesRuleForFamily(req.Family, chain, 2, "DROP", proto, "", "", iptablesPort(port), "", iface, "")
		nftAccept := buildNftablesRule(req.Family, chain, "accept", proto, src, "", nftPort(port), "", iface, "")
		nftDrop := buildNftablesRule(req.Family, chain, "drop", proto, "", "", nftPort(port), "", iface, "")
		cmds = append(cmds,
			CommandVariant{Label: "iptables", Command: iptAccept + "\n" + iptDrop,
				Note: "显式插入第 1、2 位：先放行指定 IP，再阻止该端口的其他来源"},
			CommandVariant{Label: "nftables", Command: nftAccept + "\n" + nftDrop,
				Note: "规则按书写顺序评估"},
			CommandVariant{Label: "firewalld", Command: buildFirewalldRichCommands(req,
				buildFirewalldRichRule(req, "accept", true, `priority="-100"`),
				buildFirewalldRichRule(req, "drop", false, `priority="-90"`)), Note: "先允许指定来源，再拒绝端口的其他来源"},
		)

	case "restrict_port":
		iptCmd := buildIptablesNegatedSourceRule(req.Family, chain, proto, src, iptablesPort(port), iface)
		nftCmd := buildNftablesRule(req.Family, chain, "drop", proto, "!"+src, "", nftPort(port), "", iface, "")
		cmds = append(cmds,
			CommandVariant{Label: "iptables", Command: iptCmd, Note: "拒绝非内网来源（! 表示取反）"},
			CommandVariant{Label: "nftables", Command: nftCmd, Note: "nftables 的来源 != 表达式位于动作之前"},
			CommandVariant{Label: "firewalld", Command: buildFirewalldRichCommands(req,
				buildFirewalldRichRule(req, "accept", true, `priority="-100"`),
				buildFirewalldRichRule(req, "drop", false, `priority="-90"`)), Note: "使用明确的允许与拒绝规则，避免含糊的来源取反"},
		)

	case "limit_rate":
		iptablesBin := "iptables"
		if req.Family == "ipv6" {
			iptablesBin = "ip6tables"
		}
		cmds = append(cmds,
			CommandVariant{
				Label: "iptables",
				Command: fmt.Sprintf(
					"# 限制端口 %s 的连接速率（每分钟最多 10 个新连接）\n"+
						"%s -I %s -p %s --dport %s -m conntrack --ctstate NEW -m recent --set\n"+
						"%s -I %s -p %s --dport %s -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP",
					port, iptablesBin, chain, proto, iptablesPort(port), iptablesBin, chain, proto, iptablesPort(port)),
				Note: "第1条记录连接，第2条超过阈值则丢弃",
			},
			CommandVariant{Label: "firewalld", Command: buildFirewalldRichCommands(req,
				buildFirewalldRichRule(req, `drop limit value="10/m"`, false)), Note: "生成 firewalld rich rule 限速动作，执行前需审核语义"},
		)
		if targetBackend == "all" || targetBackend == "nftables" {
			warnings = append(warnings, "未生成 nftables 限速命令：不同版本对按来源 meter/set 的语法和语义差异较大，不能用全局 limit 冒充单 IP 限速。")
		}

	default:
		warnings = append(warnings, "未知场景: "+req.Scenario)
	}

	if chain != "INPUT" {
		cmds = filterCommandVariants(cmds, "!firewalld")
		if targetBackend == "firewalld" || targetBackend == "all" {
			warnings = append(warnings, "firewalld Zone 只表达宿主机入站语义，不能为 FORWARD/DOCKER_USER 生成等价命令。")
		}
	}

	if chain == "DOCKER-USER" && port != "" {
		for i := range cmds {
			switch strings.ToLower(cmds[i].Label) {
			case "iptables":
				cmds[i].Command = strings.ReplaceAll(cmds[i].Command, "--dport "+iptablesPort(port), "-m conntrack --ctorigdstport "+iptablesPort(port)+" --ctdir ORIGINAL")
			case "nftables":
				cmds[i].Command = strings.ReplaceAll(cmds[i].Command, proto+" dport "+nftPort(port), "ct direction original ct original proto-dst "+nftPort(port))
			}
		}
		warnings = append(warnings, "DOCKER_USER 中的端口按 DNAT 前的宿主机发布端口解释，并限定连接跟踪 ORIGINAL 方向，避免兜底 DROP 拦截容器返回包。")
	}
	return filterCommandVariants(cmds, targetBackend), warnings
}

func filterCommandVariants(cmds []CommandVariant, backend string) []CommandVariant {
	if backend == "!firewalld" {
		var filtered []CommandVariant
		for _, cmd := range cmds {
			if !strings.EqualFold(cmd.Label, "firewalld") {
				filtered = append(filtered, cmd)
			}
		}
		return filtered
	}
	if backend == "" || backend == "all" {
		return cmds
	}
	var filtered []CommandVariant
	for _, cmd := range cmds {
		if strings.EqualFold(cmd.Label, backend) {
			filtered = append(filtered, cmd)
		}
	}
	return filtered
}

var safeAssistantName = regexp.MustCompile(`^[A-Za-z0-9_.+@-]+$`)

func normalizeAndValidateGenerateRequest(req *GenerateRequest) error {
	req.Scenario = strings.ToLower(strings.TrimSpace(req.Scenario))
	req.Chain = strings.ToUpper(strings.TrimSpace(req.Chain))
	if req.Chain == "DOCKER-USER" {
		req.Chain = "DOCKER_USER"
	}
	req.Backend = strings.ToLower(strings.TrimSpace(req.Backend))
	if req.Backend == "" {
		req.Backend = "all"
	}
	if req.Backend == "nft" {
		req.Backend = "nftables"
	}
	req.Protocol = strings.ToLower(strings.TrimSpace(req.Protocol))
	req.Family = strings.ToLower(strings.TrimSpace(req.Family))
	req.Zone = strings.TrimSpace(req.Zone)
	if req.Zone == "" {
		req.Zone = "public"
	}
	req.Source = strings.TrimSpace(req.Source)
	req.Port = strings.TrimSpace(req.Port)
	req.Interface = strings.TrimSpace(req.Interface)

	validScenario := map[string]bool{"block_port": true, "allow_ip": true, "allow_ip_port": true, "restrict_port": true, "limit_rate": true}
	if !validScenario[req.Scenario] {
		return fmt.Errorf("unsupported scenario %q", req.Scenario)
	}
	validBackend := map[string]bool{"all": true, "iptables": true, "nftables": true, "firewalld": true}
	if !validBackend[req.Backend] {
		return fmt.Errorf("unsupported backend %q", req.Backend)
	}
	validChain := map[string]bool{"INPUT": true, "FORWARD": true, "DOCKER_USER": true}
	if !validChain[req.Chain] {
		return fmt.Errorf("unsupported chain %q", req.Chain)
	}
	if req.Backend == "firewalld" && req.Chain != "INPUT" {
		return fmt.Errorf("firewalld command generation only supports INPUT semantics")
	}
	if req.Chain == "DOCKER_USER" && req.Scenario == "allow_ip" {
		return fmt.Errorf("DOCKER_USER does not support an all-port source whitelist because a blanket fallback DROP can block container return traffic; choose allow_ip_port")
	}
	if req.Family != "" && req.Family != "ipv4" && req.Family != "ipv6" {
		return fmt.Errorf("family must be ipv4, ipv6, or empty")
	}
	if req.Protocol != "tcp" && req.Protocol != "udp" && req.Protocol != "all" {
		return fmt.Errorf("protocol must be tcp, udp, or all")
	}
	if !safeAssistantName.MatchString(req.Zone) {
		return fmt.Errorf("zone contains unsupported characters")
	}
	if req.Interface != "" && !safeAssistantName.MatchString(req.Interface) {
		return fmt.Errorf("interface contains unsupported characters")
	}
	if req.Source != "" {
		ip := net.ParseIP(req.Source)
		if ip == nil {
			var err error
			ip, _, err = net.ParseCIDR(req.Source)
			if err != nil {
				return fmt.Errorf("source must be an IP address or CIDR")
			}
		}
		isIPv6 := ip.To4() == nil
		if req.Family == "ipv4" && isIPv6 {
			return fmt.Errorf("source is IPv6 but family is ipv4")
		}
		if req.Family == "ipv6" && !isIPv6 {
			return fmt.Errorf("source is IPv4 but family is ipv6")
		}
		if req.Family == "" {
			if isIPv6 {
				req.Family = "ipv6"
			} else {
				req.Family = "ipv4"
			}
		}
	}
	requiresSource := req.Scenario == "allow_ip" || req.Scenario == "allow_ip_port" || req.Scenario == "restrict_port"
	if requiresSource && req.Source == "" {
		return fmt.Errorf("source is required for this scenario")
	}
	requiresPort := req.Scenario != "allow_ip"
	if requiresPort {
		if req.Port == "" {
			return fmt.Errorf("port is required for this scenario")
		}
		if err := validateAssistantPort(req.Port); err != nil {
			return err
		}
		if req.Protocol != "tcp" && req.Protocol != "udp" {
			return fmt.Errorf("a port match requires tcp or udp protocol")
		}
	}
	if req.Scenario == "limit_rate" && req.Backend == "nftables" {
		return fmt.Errorf("nftables per-source rate limiting is intentionally not generated; use iptables and review the semantics")
	}
	return nil
}

func validateAssistantPort(value string) error {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ':' || r == '-' })
	if len(parts) < 1 || len(parts) > 2 {
		return fmt.Errorf("port must be a number or range such as 8000:9000")
	}
	for _, part := range parts {
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("port must be between 1 and 65535")
		}
	}
	if len(parts) == 2 {
		first, _ := strconv.Atoi(parts[0])
		last, _ := strconv.Atoi(parts[1])
		if first > last {
			return fmt.Errorf("port range start must not exceed its end")
		}
	}
	return nil
}

func commandChain(chain string) string {
	if chain == "DOCKER_USER" {
		return "DOCKER-USER"
	}
	return chain
}

func iptablesPort(port string) string { return strings.ReplaceAll(port, "-", ":") }
func nftPort(port string) string      { return strings.ReplaceAll(port, ":", "-") }

func buildIptablesRuleForFamily(family, chain string, position int, action, proto, src, dest, dport, sport, iface, comment string) string {
	var parts []string
	bin := "iptables"
	if strings.EqualFold(family, "ipv6") {
		bin = "ip6tables"
	}
	parts = append(parts, bin)

	if chain != "" {
		parts = append(parts, "-I", chain)
		if position > 0 {
			parts = append(parts, strconv.Itoa(position))
		}
	}
	if proto != "" && proto != "all" {
		parts = append(parts, "-p", proto)
	}
	if src != "" {
		parts = append(parts, "-s", src)
	}
	if dest != "" {
		parts = append(parts, "-d", dest)
	}
	if dport != "" {
		parts = append(parts, "--dport", dport)
	}
	if sport != "" {
		parts = append(parts, "--sport", sport)
	}
	if iface != "" {
		parts = append(parts, "-i", iface)
	}
	if action != "" {
		parts = append(parts, "-j", action)
	}
	if comment != "" {
		parts = append(parts, "-m", "comment", "--comment", comment)
	}

	return strings.Join(parts, " ")
}

func buildIptablesNegatedSourceRule(family, chain, proto, src, dport, iface string) string {
	cmd := buildIptablesRuleForFamily(family, chain, 1, "DROP", proto, "", "", dport, "", iface, "")
	needle := " --dport"
	negated := " ! -s " + src
	if strings.Contains(cmd, needle) {
		return strings.Replace(cmd, needle, negated+needle, 1)
	}
	return strings.Replace(cmd, " -j DROP", negated+" -j DROP", 1)
}

func buildNftablesRule(family, chain, action, proto, src, dest, dport, sport, iface, _ string) string {
	nftFamily := "ip"
	if strings.EqualFold(family, "ipv6") {
		nftFamily = "ip6"
	}
	parts := []string{"nft", "add", "rule", nftFamily, "filter", chain}
	if iface != "" {
		parts = append(parts, "iifname", iface)
	}
	if src != "" {
		if strings.HasPrefix(src, "!") {
			parts = append(parts, nftFamily, "saddr", "!=", strings.TrimPrefix(src, "!"))
		} else {
			parts = append(parts, nftFamily, "saddr", src)
		}
	}
	if dest != "" {
		parts = append(parts, nftFamily, "daddr", dest)
	}
	if proto != "" && proto != "all" {
		parts = append(parts, proto)
	}
	if dport != "" {
		parts = append(parts, "dport", dport)
	}
	if sport != "" {
		parts = append(parts, "sport", sport)
	}
	if action != "" {
		parts = append(parts, action)
	}
	return strings.Join(parts, " ")
}

func buildFirewalldRichRule(req GenerateRequest, action string, includeSource bool, extras ...string) string {
	parts := []string{"rule"}
	if req.Family == "ipv4" || req.Family == "ipv6" {
		parts = append(parts, fmt.Sprintf(`family="%s"`, req.Family))
	}
	parts = append(parts, extras...)
	if includeSource && req.Source != "" {
		parts = append(parts, fmt.Sprintf(`source address="%s"`, req.Source))
	}
	if req.Port != "" {
		parts = append(parts, fmt.Sprintf(`port port="%s" protocol="%s"`, nftPort(req.Port), req.Protocol))
	}
	if action != "" {
		parts = append(parts, action)
	}
	return strings.Join(parts, " ")
}

func buildFirewalldRichCommands(req GenerateRequest, richRules ...string) string {
	commands := make([]string, 0, len(richRules)+1)
	for _, richRule := range richRules {
		if strings.TrimSpace(richRule) == "" {
			continue
		}
		parts := []string{"firewall-cmd", "--zone=" + req.Zone}
		if req.Permanent {
			parts = append(parts, "--permanent")
		}
		parts = append(parts, "--add-rich-rule='"+richRule+"'")
		commands = append(commands, strings.Join(parts, " "))
	}
	if req.Permanent && len(commands) > 0 {
		commands = append(commands, "firewall-cmd --reload")
	}
	return strings.Join(commands, "\n")
}

// iptables command parser
var (
	iptChainRe         = regexp.MustCompile(`-A\s+(\S+)|-I\s+(\S+)(?:\s+\d+)?|--append\s+(\S+)|--insert\s+(\S+)`)
	iptProtoRe         = regexp.MustCompile(`-p\s+(\S+)|--protocol\s+(\S+)`)
	iptSrcRe           = regexp.MustCompile(`-s\s+(\S+)|--source\s+(\S+)`)
	iptDstRe           = regexp.MustCompile(`-d\s+(\S+)|--destination\s+(\S+)`)
	iptDportRe         = regexp.MustCompile(`--dport\s+(\S+)`)
	iptOriginalDportRe = regexp.MustCompile(`--ctorigdstport\s+(\S+)`)
	iptDirectionRe     = regexp.MustCompile(`--ctdir\s+(\S+)`)
	iptSportRe         = regexp.MustCompile(`--sport\s+(\S+)`)
	iptActionRe        = regexp.MustCompile(`-j\s+(\S+)|--jump\s+(\S+)`)
	iptIfaceRe         = regexp.MustCompile(`-i\s+(\S+)|--in-interface\s+(\S+)`)
	iptStateRe         = regexp.MustCompile(`--ctstate\s+(\S+)|-m\s+conntrack\s+--ctstate\s+(\S+)`)
	iptCommentRe       = regexp.MustCompile(`--comment\s+(.+?)(?:\s+-|$)`)
)

func explainCommand(input string) (string, []string) {
	var commands []string
	for _, line := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			commands = append(commands, line)
		}
	}
	if len(commands) == 0 {
		return "无法识别命令类型。请输入 iptables、ip6tables、nft 或 firewall-cmd 命令。", nil
	}
	if len(commands) == 1 {
		return explainSingleCommand(commands[0])
	}

	var explanations []string
	var warnings []string
	for i, command := range commands {
		explanation, commandWarnings := explainSingleCommand(command)
		explanation = strings.Replace(explanation, "### 命令解读", fmt.Sprintf("### 命令 %d", i+1), 1)
		explanations = append(explanations, explanation)
		warnings = append(warnings, commandWarnings...)
	}
	if strings.Contains(input, "firewall-cmd --reload") {
		var filtered []string
		for _, warning := range warnings {
			if !strings.Contains(warning, "永久规则需要执行 firewall-cmd --reload") {
				filtered = append(filtered, warning)
			}
		}
		warnings = filtered
	}
	allImplicitInsert := true
	insertCount := 0
	for _, command := range commands {
		if strings.HasPrefix(command, "iptables") || strings.HasPrefix(command, "ip6tables") {
			if regexp.MustCompile(`(?:^|\s)-I\s+\S+`).MatchString(command) {
				insertCount++
				if regexp.MustCompile(`(?:^|\s)-I\s+\S+\s+\d+(?:\s|$)`).MatchString(command) {
					allImplicitInsert = false
				}
			}
		}
	}
	if insertCount > 1 && allImplicitInsert {
		warnings = append(warnings, "连续执行多条未指定位置的 iptables -I 命令会把后执行的规则插到最前面，最终顺序与文本顺序相反。")
	}
	return strings.Join(explanations, "\n\n"), warnings
}

func explainSingleCommand(cmd string) (string, []string) {
	cmd = strings.TrimSpace(cmd)
	var warnings []string
	var parts []string

	isNft := strings.HasPrefix(cmd, "nft ")
	isIptables := strings.HasPrefix(cmd, "iptables") || strings.HasPrefix(cmd, "iptables-") || strings.HasPrefix(cmd, "ip6tables")
	isFirewalld := strings.HasPrefix(cmd, "firewall-cmd")
	if !isNft && !isIptables && !isFirewalld {
		return "无法识别命令类型。请输入 iptables、ip6tables、nft 或 firewall-cmd 命令。", nil
	}

	parts = append(parts, "### 命令解读\n")

	if isIptables {
		parts = append(parts, "**类型**: iptables 规则")
		parts = append(parts, explainIptables(cmd, &warnings)...)
	} else if isNft {
		parts = append(parts, "**类型**: nftables 规则")
		parts = append(parts, explainNftCommand(cmd, &warnings)...)
	} else {
		parts = append(parts, "**类型**: firewalld 命令")
		parts = append(parts, explainFirewalldCommand(cmd, &warnings)...)
	}

	return strings.Join(parts, "\n"), warnings
}

func explainFirewalldCommand(cmd string, warnings *[]string) []string {
	var parts []string
	for _, field := range strings.Fields(cmd) {
		if strings.HasPrefix(field, "--zone=") {
			parts = append(parts, fmt.Sprintf("- **Zone**: `%s`", strings.TrimPrefix(field, "--zone=")))
		}
		if field == "--permanent" {
			parts = append(parts, "- **持久化**: 是")
		}
	}
	if strings.Contains(cmd, "--add-rich-rule=") {
		parts = append(parts, "- **操作**: 添加 rich rule")
	} else if strings.Contains(cmd, "--remove-rich-rule=") {
		parts = append(parts, "- **操作**: 删除 rich rule")
	} else if value := firewalldOptionValue(cmd, "--add-port"); value != "" {
		parts = append(parts, fmt.Sprintf("- **操作**: 放行端口 `%s`", value))
	} else if value := firewalldOptionValue(cmd, "--remove-port"); value != "" {
		parts = append(parts, fmt.Sprintf("- **操作**: 移除端口放行 `%s`", value))
	} else if value := firewalldOptionValue(cmd, "--add-service"); value != "" {
		parts = append(parts, fmt.Sprintf("- **操作**: 放行服务 `%s`", value))
	} else if value := firewalldOptionValue(cmd, "--remove-service"); value != "" {
		parts = append(parts, fmt.Sprintf("- **操作**: 移除服务放行 `%s`", value))
	} else if strings.Contains(cmd, "--list-all") {
		parts = append(parts, "- **操作**: 查看 Zone 配置")
	} else if strings.Contains(cmd, "--get-active-zones") {
		parts = append(parts, "- **操作**: 查看活动 Zone")
	} else if strings.Contains(cmd, "--reload") {
		parts = append(parts, "- **操作**: 重载永久配置到运行态")
	}
	if strings.Contains(cmd, `family="ipv4"`) {
		parts = append(parts, "- **地址族**: `ipv4`")
	} else if strings.Contains(cmd, `family="ipv6"`) {
		parts = append(parts, "- **地址族**: `ipv6`")
	}
	if value := extractQuotedValue(cmd, `source address="`); value != "" {
		parts = append(parts, fmt.Sprintf("- **来源地址**: `%s`", value))
	}
	if value := extractQuotedValue(cmd, `port port="`); value != "" {
		parts = append(parts, fmt.Sprintf("- **目标端口**: `%s`", value))
	}
	if value := extractQuotedValue(cmd, `protocol="`); value != "" {
		parts = append(parts, fmt.Sprintf("- **协议**: `%s`", value))
	}
	for _, action := range []string{"accept", "drop", "reject"} {
		if strings.Contains(cmd, " "+action) || strings.Contains(cmd, action+" ") {
			parts = append(parts, fmt.Sprintf("- **动作**: `%s` (%s)", action, actionNameCN(strings.ToUpper(action))))
			break
		}
	}
	if strings.Contains(cmd, "--permanent") && !strings.Contains(cmd, "--reload") {
		*warnings = append(*warnings, "永久规则需要执行 firewall-cmd --reload 后才会同步到运行配置。")
	}
	if strings.Contains(cmd, `source address="`) && !strings.Contains(cmd, `family="`) {
		*warnings = append(*warnings, "rich rule 使用来源地址时建议指定 family=\"ipv4\" 或 family=\"ipv6\"。")
	}
	if strings.Contains(cmd, " drop") && !strings.Contains(cmd, `port port="`) && !strings.Contains(cmd, `source address="`) {
		*warnings = append(*warnings, "⚠ 该 rich rule 可能拒绝整个 Zone 的广泛流量，请确认来源和 priority。")
	}
	return parts
}

func firewalldOptionValue(command, option string) string {
	fields := strings.Fields(command)
	for index, field := range fields {
		if strings.HasPrefix(field, option+"=") {
			return strings.Trim(strings.TrimPrefix(field, option+"="), "'\"")
		}
		if field == option && index+1 < len(fields) {
			return strings.Trim(fields[index+1], "'\"")
		}
	}
	return ""
}

func extractQuotedValue(value, prefix string) string {
	index := strings.Index(value, prefix)
	if index < 0 {
		return ""
	}
	rest := value[index+len(prefix):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func explainIptables(cmd string, warnings *[]string) []string {
	var parts []string

	// Extract chain
	chain := extractFirst(iptChainRe, cmd)
	if chain != "" {
		chainName := chainNameCN(chain)
		parts = append(parts, fmt.Sprintf("- **目标链**: `%s` (%s)", chain, chainName))
	}

	// Extract action
	action := extractFirst(iptActionRe, cmd)
	if action != "" {
		actionName := actionNameCN(action)
		parts = append(parts, fmt.Sprintf("- **动作**: `%s` (%s)", action, actionName))
	}

	// Extract protocol
	proto := extractFirst(iptProtoRe, cmd)
	if proto != "" && proto != "all" {
		parts = append(parts, fmt.Sprintf("- **协议**: `%s`", proto))
	}

	// Extract source
	src := extractFirst(iptSrcRe, cmd)
	if src != "" && src != "0.0.0.0/0" {
		parts = append(parts, fmt.Sprintf("- **来源地址**: `%s`", src))
	}

	// Extract dest
	dst := extractFirst(iptDstRe, cmd)
	if dst != "" && dst != "0.0.0.0/0" {
		parts = append(parts, fmt.Sprintf("- **目标地址**: `%s`", dst))
	}

	// Extract port
	dport := extractFirst(iptDportRe, cmd)
	if dport != "" {
		parts = append(parts, fmt.Sprintf("- **目标端口**: `%s`", dport))
	}
	originalDport := extractFirst(iptOriginalDportRe, cmd)
	if originalDport != "" {
		parts = append(parts, fmt.Sprintf("- **Docker 映射前的宿主机端口**: `%s`（连接跟踪 original destination port）", originalDport))
		if dport != "" {
			*warnings = append(*warnings, fmt.Sprintf("⚠ 同时指定了普通 dport=%s 和 Docker 原始端口=%s。DOCKER-USER 中普通 dport 是 DNAT 后的容器端口；若宿主机 %s 映射到其他容器端口，这条规则不会命中。仅按发布端口限制时请删除普通 --dport。", dport, originalDport, originalDport))
		}
		direction := strings.ToUpper(extractFirst(iptDirectionRe, cmd))
		if direction != "" {
			parts = append(parts, fmt.Sprintf("- **连接方向**: `%s`", direction))
		} else if action == "DROP" || action == "REJECT" {
			*warnings = append(*warnings, "⚠ Docker 原始目标端口的兜底阻止规则没有 --ctdir ORIGINAL，可能同时拦截容器返回包并导致客户端超时。")
		}
	}
	sport := extractFirst(iptSportRe, cmd)
	if sport != "" {
		parts = append(parts, fmt.Sprintf("- **来源端口**: `%s`", sport))
	}

	// Extract interface
	iface := extractFirst(iptIfaceRe, cmd)
	if iface != "" {
		parts = append(parts, fmt.Sprintf("- **入站接口**: `%s`", iface))
	}

	// Extract state
	state := extractFirst(iptStateRe, cmd)
	if state != "" {
		parts = append(parts, fmt.Sprintf("- **连接状态**: `%s`", state))
	}

	// Extract comment
	comment := extractComment(iptCommentRe, cmd)
	if comment != "" {
		parts = append(parts, fmt.Sprintf("- **备注**: %s", comment))
	}

	// Summary
	if action == "DROP" || action == "REJECT" {
		parts = append(parts, "\n> 这条规则会**阻止**匹配的流量。")
	} else if action == "ACCEPT" {
		parts = append(parts, "\n> 这条规则会**放行**匹配的流量。")
	} else if action == "LOG" {
		parts = append(parts, "\n> 这条规则会**记录日志**但不阻止流量。")
	}

	// Safety warnings
	if chain == "INPUT" && (action == "DROP" || action == "REJECT") && dport == "" && src == "" {
		*warnings = append(*warnings, "⚠ 此规则会阻止所有进入主机的流量，可能导致 SSH 断开！建议指定端口或来源 IP。")
	}
	if strings.Contains(cmd, "-F") || strings.Contains(cmd, "--flush") {
		*warnings = append(*warnings, "⚠ 该命令会清空链中所有规则，谨慎执行！")
	}

	return parts
}

func explainNftCommand(cmd string, warnings *[]string) []string {
	var parts []string
	fields := strings.Fields(cmd)

	if len(fields) >= 6 && fields[0] == "nft" && fields[1] == "add" && fields[2] == "rule" {
		parts = append(parts,
			"- **操作**: 添加规则",
			fmt.Sprintf("- **地址族**: `%s`", fields[3]),
			fmt.Sprintf("- **目标表**: `%s`", fields[4]),
			fmt.Sprintf("- **目标链**: `%s` (%s)", fields[5], chainNameCN(fields[5])),
		)
	}
	for i, f := range fields {
		switch f {
		case "tcp", "udp", "icmp":
			parts = append(parts, fmt.Sprintf("- **协议**: `%s`", f))
		case "dport":
			if i+1 < len(fields) {
				parts = append(parts, fmt.Sprintf("- **目标端口**: `%s`", fields[i+1]))
			}
		case "proto-dst":
			if i >= 2 && fields[i-2] == "ct" && fields[i-1] == "original" && i+1 < len(fields) {
				parts = append(parts, fmt.Sprintf("- **Docker 映射前的宿主机端口**: `%s`", fields[i+1]))
			}
		case "sport":
			if i+1 < len(fields) {
				parts = append(parts, fmt.Sprintf("- **来源端口**: `%s`", fields[i+1]))
			}
		case "saddr":
			if i+1 < len(fields) {
				parts = append(parts, fmt.Sprintf("- **来源地址**: `%s`", fields[i+1]))
			}
		case "daddr":
			if i+1 < len(fields) {
				parts = append(parts, fmt.Sprintf("- **目标地址**: `%s`", fields[i+1]))
			}
		case "iifname":
			if i+1 < len(fields) {
				parts = append(parts, fmt.Sprintf("- **入站接口**: `%s`", fields[i+1]))
			}
		case "drop", "accept", "reject", "log", "return":
			parts = append(parts, fmt.Sprintf("- **动作**: `%s` (%s)", f, actionNameCN(strings.ToUpper(f))))
		}
	}
	joined := " " + strings.Join(fields, " ") + " "
	if strings.Contains(joined, " dport ") && strings.Contains(joined, " ct original proto-dst ") {
		*warnings = append(*warnings, "⚠ 同时匹配了 DNAT 后目标端口和 Docker 原始目标端口；请确认 dport 填的是容器端口。仅按宿主机发布端口限制时应删除普通 dport。")
	}
	if strings.Contains(joined, " ct original proto-dst ") && (strings.Contains(joined, " drop ") || strings.Contains(joined, " reject ")) && !strings.Contains(joined, " ct direction original ") {
		*warnings = append(*warnings, "⚠ Docker 原始目标端口的兜底阻止规则没有限定 ct direction original，可能拦截返回包。")
	}
	if strings.Contains(joined, " drop ") && !strings.Contains(joined, " dport ") && !strings.Contains(joined, " ct original proto-dst ") && !strings.Contains(joined, " saddr ") {
		*warnings = append(*warnings, "⚠ 该 nftables 规则可能丢弃目标链中的广泛流量，请确认作用范围。")
	}

	return parts
}

func extractFirst(re *regexp.Regexp, s string) string {
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		return ""
	}
	for i := 1; i < len(matches); i++ {
		if matches[i] != "" {
			return matches[i]
		}
	}
	return ""
}

func extractComment(re *regexp.Regexp, s string) string {
	matches := re.FindStringSubmatch(s)
	if matches == nil || len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

func chainNameCN(chain string) string {
	names := map[string]string{
		"INPUT":       "入站流量",
		"FORWARD":     "转发流量",
		"OUTPUT":      "出站流量",
		"DOCKER":      "Docker 端口映射（系统管理）",
		"DOCKER_USER": "Docker 用户自定义规则",
		"DOCKER-USER": "Docker 用户自定义规则",
	}
	if n, ok := names[chain]; ok {
		return n
	}
	return chain
}

func actionNameCN(action string) string {
	names := map[string]string{
		"ACCEPT": "允许通过",
		"DROP":   "静默丢弃",
		"REJECT": "拒绝并返回错误",
		"LOG":    "记录日志",
		"RETURN": "返回上级链",
	}
	if n, ok := names[strings.ToUpper(action)]; ok {
		return n
	}
	return action
}
