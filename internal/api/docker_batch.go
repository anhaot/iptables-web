package api

import (
	"fmt"
	"iptables-web/internal/model"
	"iptables-web/internal/store"
	"net/http"
	"strings"
	"time"
)

const maxBatchDeleteRules = 1000

type batchDeleteRulesRequest struct {
	RuleIDs           []string             `json:"rule_ids"`
	ExpectedUpdatedAt map[string]time.Time `json:"expected_updated_at,omitempty"`
}

func (h *Handler) BatchDeleteRules(w http.ResponseWriter, r *http.Request) {
	var req batchDeleteRulesRequest
	if err := decodeJSONBody(w, r, &req, 1024*1024); err != nil {
		respondError(w, 400, "invalid_json", err.Error())
		return
	}
	if len(req.RuleIDs) == 0 || len(req.RuleIDs) > maxBatchDeleteRules {
		respondError(w, 400, "validation_error", "rule_ids 必须包含 1-1000 条规则")
		return
	}
	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()
	snapshot := h.snapshotRules()
	byID := make(map[string]*model.Rule, len(snapshot))
	for _, rule := range snapshot {
		byID[rule.ID] = rule
	}
	selected := make(map[string]bool, len(req.RuleIDs))
	removed := make([]*model.Rule, 0, len(req.RuleIDs))
	targets := map[string]bool{}
	for _, id := range req.RuleIDs {
		if id == "" || selected[id] {
			respondError(w, 400, "validation_error", "规则 ID 不能为空或重复")
			return
		}
		rule := byID[id]
		if rule == nil {
			respondError(w, 409, "rules_changed", "规则已经变化，请刷新后重新选择")
			return
		}
		if len(req.ExpectedUpdatedAt) > 0 {
			expected, ok := req.ExpectedUpdatedAt[id]
			if !ok || !expected.Equal(rule.UpdatedAt) {
				respondError(w, 409, "rules_changed", "规则已被修改，请刷新后重新确认")
				return
			}
		}
		selected[id] = true
		removed = append(removed, rule)
		targets[rule.Chain] = true
	}
	if len(req.ExpectedUpdatedAt) > 0 && len(req.ExpectedUpdatedAt) != len(selected) {
		respondError(w, 400, "validation_error", "expected_updated_at 必须与 rule_ids 一致")
		return
	}
	desired := make([]*model.Rule, 0, len(snapshot)-len(removed))
	for _, rule := range snapshot {
		if !selected[rule.ID] {
			desired = append(desired, rule)
		}
	}
	if err := h.applyManagedBatch(snapshot, desired, removed, nil, targets); err != nil {
		respondError(w, 500, "batch_apply_failed", err.Error())
		return
	}
	respondOK(w, map[string]interface{}{"removed": len(removed)})
}

type dockerWhitelistBatchRequest struct {
	Sources  []string                 `json:"sources"`
	Mappings []dockerWhitelistRequest `json:"mappings"`
}

type dockerWhitelistPlan struct {
	allow       *model.Rule
	drop        *model.Rule
	added       []*model.Rule
	createdDrop bool
}

func (h *Handler) CreateDockerWhitelist(w http.ResponseWriter, r *http.Request) {
	var req dockerWhitelistRequest
	if err := decodeJSONBody(w, r, &req, defaultJSONBodyLimit); err != nil {
		respondError(w, 400, "invalid_json", err.Error())
		return
	}
	h.createDockerWhitelists(w, []dockerWhitelistRequest{req}, true)
}

func (h *Handler) CreateDockerWhitelistBatch(w http.ResponseWriter, r *http.Request) {
	var req dockerWhitelistBatchRequest
	if err := decodeJSONBody(w, r, &req, 1024*1024); err != nil {
		respondError(w, 400, "invalid_json", err.Error())
		return
	}
	if len(req.Mappings) == 0 || len(req.Mappings) > 50 || len(req.Sources) == 0 || len(req.Sources) > 100 || len(req.Mappings)*len(req.Sources) > 200 {
		respondError(w, 400, "validation_error", "请选择 1-50 个发布端口、1-100 个来源，每批最多 200 个来源与端口组合")
		return
	}
	items := make([]dockerWhitelistRequest, 0, len(req.Mappings)*len(req.Sources))
	for _, mapping := range req.Mappings {
		for _, source := range req.Sources {
			item := mapping
			item.Source = source
			items = append(items, item)
		}
	}
	h.createDockerWhitelists(w, items, false)
}

func (h *Handler) createDockerWhitelists(w http.ResponseWriter, requests []dockerWhitelistRequest, single bool) {
	h.mutationMu.Lock()
	defer h.mutationMu.Unlock()
	snapshot := h.snapshotRules()
	// All planning uses a detached in-memory store: a late invalid source or
	// mapping cannot persist or execute any prefix of the request.
	staged := store.NewJSONStore("")
	if err := staged.ReplaceAll(snapshot); err != nil {
		respondError(w, 500, "store_error", err.Error())
		return
	}
	plans := make([]dockerWhitelistPlan, 0, len(requests))
	added := []*model.Rule{}
	allows, drops, skipped := 0, 0, 0
	for _, req := range requests {
		plan, err := planDockerWhitelist(staged, req)
		if err != nil {
			respondError(w, 400, "validation_error", err.Error())
			return
		}
		plans = append(plans, plan)
		added = append(added, plan.added...)
		addedAllow := false
		for _, rule := range plan.added {
			if rule.Action == "ACCEPT" {
				allows++
				addedAllow = true
			}
		}
		if !addedAllow {
			skipped++
		}
		if plan.createdDrop {
			drops++
		}
	}
	ordered, err := staged.ListByTarget(model.BackendPacket, "DOCKER_USER")
	if err != nil {
		respondError(w, 500, "store_error", err.Error())
		return
	}
	if err := validateOrderedRules("DOCKER_USER", ordered); err != nil {
		respondError(w, 400, "unsafe_order", err.Error())
		return
	}
	path := h.executor.DockerPathStatus()
	if !path.Usable {
		respondError(w, 409, "docker_path_unavailable", path.Message)
		return
	}
	if len(added) > 0 {
		desired, _ := staged.All()
		if err := h.applyManagedBatch(snapshot, desired, nil, added, map[string]bool{"DOCKER_USER": true}); err != nil {
			respondError(w, 500, "batch_apply_failed", err.Error())
			return
		}
	}
	if single {
		plan := plans[0]
		data := map[string]interface{}{"created": len(added) > 0, "created_drop": plan.createdDrop, "allow_rule": plan.allow, "drop_rule": plan.drop}
		if len(added) == 0 {
			respondOK(w, data)
		} else {
			respondCreated(w, data)
		}
		return
	}
	respondOK(w, map[string]interface{}{"added_sources": allows, "added_fallbacks": drops, "skipped_sources": skipped})
}

func planDockerWhitelist(staged *store.JSONStore, req dockerWhitelistRequest) (dockerWhitelistPlan, error) {
	plan := dockerWhitelistPlan{}
	if req.HostPort < 1 || req.HostPort > 65535 || req.ContainerPort < 1 || req.ContainerPort > 65535 {
		return plan, fmt.Errorf("host_port 和 container_port 必须为 1-65535")
	}
	if strings.TrimSpace(req.Source) == "" {
		return plan, fmt.Errorf("来源 IPv4/CIDR 不能为空")
	}
	if dockerAddressFamily(req.HostIP) != "ipv4" {
		return plan, fmt.Errorf("IPv6 Docker 映射只读")
	}
	proto := strings.ToLower(strings.TrimSpace(req.Protocol))
	if proto == "" {
		proto = "tcp"
	}
	allow := &model.Rule{Backend: model.BackendPacket, Chain: "DOCKER_USER", Action: "ACCEPT", Protocol: proto, Source: req.Source, OriginalDPort: fmt.Sprint(req.HostPort), Position: 1, Enabled: true}
	hostIP := strings.Trim(strings.TrimSpace(req.HostIP), "[]")
	if hostIP != "" && hostIP != "0.0.0.0" {
		allow.OriginalDest = hostIP
	}
	if err := allow.Validate(); err != nil {
		return plan, err
	}
	rules, err := staged.ListByTarget(model.BackendPacket, "DOCKER_USER")
	if err != nil {
		return plan, err
	}
	maxPosition := 0
	for _, existing := range rules {
		if existing.Position > maxPosition {
			maxPosition = existing.Position
		}
		if existing.Enabled && allow.OriginalDest != "" && existing.OriginalDest == "" && strings.EqualFold(existing.Protocol, proto) && existing.OriginalDPort == allow.OriginalDPort && isDockerFallback(existing) {
			return plan, fmt.Errorf("已有作用于所有宿主机 IP 的兜底规则；请先核对其范围，再添加指定地址的白名单")
		}
		if !existing.Enabled || !strings.EqualFold(existing.Protocol, proto) || existing.OriginalDPort != allow.OriginalDPort || existing.OriginalDest != allow.OriginalDest {
			continue
		}
		if existing.Action == "ACCEPT" && existing.Source == allow.Source && existing.Dest == "" && existing.SPort == "" && existing.InIface == "" && existing.OutIface == "" && existing.State == "" {
			plan.allow = existing
		}
		if plan.drop == nil && isDockerFallback(existing) {
			plan.drop = existing
		}
	}
	endpoint := dockerRuleEndpoint(req.HostIP, req.HostPort, req.ContainerName, req.ContainerPort)
	if plan.allow == nil {
		id, err := newID()
		if err != nil {
			return plan, err
		}
		allow.ID = id
		allow.Position = maxPosition + 1
		if plan.drop != nil {
			allow.Position = plan.drop.Position
		}
		allow.Desc = fmt.Sprintf("允许 %s 访问 %s", allow.Source, endpoint)
		if err := allow.Validate(); err != nil {
			return plan, err
		}
		if err := staged.Create(allow); err != nil {
			return plan, err
		}
		plan.allow = allow
		plan.added = append(plan.added, allow)
		maxPosition++
	}
	if plan.drop == nil {
		id, err := newID()
		if err != nil {
			return plan, err
		}
		drop := &model.Rule{ID: id, Backend: model.BackendPacket, Chain: "DOCKER_USER", Action: "DROP", Protocol: proto, OriginalDest: allow.OriginalDest, OriginalDPort: allow.OriginalDPort, Enabled: true, Position: maxPosition + 1, Desc: "阻止其他来源访问 " + endpoint}
		if err := drop.Validate(); err != nil {
			return plan, err
		}
		if err := staged.Create(drop); err != nil {
			return plan, err
		}
		plan.drop = drop
		plan.added = append(plan.added, drop)
		plan.createdDrop = true
	}
	return plan, nil
}

func isDockerFallback(rule *model.Rule) bool {
	return (rule.Action == "DROP" || rule.Action == "REJECT") && rule.Source == "" && rule.Dest == "" && rule.SPort == "" && rule.InIface == "" && rule.OutIface == "" && rule.State == ""
}

// File and kernel updates are serialized and compensated on failure. This is
// not a kernel-wide transaction and never flushes or claims external rules.
func (h *Handler) applyManagedBatch(snapshot, desired, removed, added []*model.Rule, targets map[string]bool) error {
	if err := h.store.ReplaceAll(desired); err != nil {
		return err
	}
	if err := h.store.Save(); err != nil {
		_ = h.store.ReplaceAll(snapshot)
		return fmt.Errorf("保存失败，未执行防火墙变更：%w", err)
	}
	applyErr := h.executor.DeleteRules(removed)
	if applyErr == nil {
		for chain := range targets {
			if err := h.syncRuleTarget(model.BackendPacket, chain); err != nil {
				applyErr = err
				break
			}
		}
	}
	if applyErr == nil {
		return nil
	}
	var recovery []string
	if err := h.executor.DeleteRules(added); err != nil {
		recovery = append(recovery, err.Error())
	}
	if err := h.store.ReplaceAll(snapshot); err != nil {
		recovery = append(recovery, err.Error())
	}
	if err := h.store.Save(); err != nil {
		recovery = append(recovery, err.Error())
	}
	for chain := range targets {
		if err := h.syncRuleTarget(model.BackendPacket, chain); err != nil {
			recovery = append(recovery, err.Error())
		}
	}
	if len(recovery) > 0 {
		return fmt.Errorf("应用失败：%v；恢复未完成，请核对运行态：%s", applyErr, strings.Join(recovery, "; "))
	}
	return fmt.Errorf("应用失败，已恢复变更前的托管规则：%w", applyErr)
}
