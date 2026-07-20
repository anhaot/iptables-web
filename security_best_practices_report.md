# iptables-web 代码、安全与功能完整性审计

## 2026-07-20 修复状态

除项目明确保留的默认外部监听、初始账号和 HTTP 部署方式外，当前源码已经处理本报告的主要可修复项：会话按当前用户重新校验并在删除/改密时撤销；用户写盘失败回滚；数据文件权限收紧；Store 返回深拷贝；Docker 白名单忽略停用规则并按原始宿主机 IP 隔离；组合备份可恢复 IPv4/IPv6 与托管元数据；restore 改为替换语义并预备回滚；托管 CRUD 明确拒绝 IPv6；启动与健康检查验证规则；iptables 命令增加所有权 comment、预检、锁等待与超时；JSON 请求统一限长；CAPTCHA 每次尝试消费；限流使用固定窗口；创建、编辑、重排统一执行顺序安全检查；日志包含请求 ID、操作者和来源地址。

默认外部监听、`admin/admin123`、HTTP 与浏览器 Token 存储风险仍按使用方决定保留，详见 SEC-AUTH-001 和 SEC-TRANSPORT-001。真实内核规则替换仍需网络命名空间集成测试验证；单元测试不能证明所有发行版的 iptables/iptables-restore 行为一致。

## 当前生产审计（2026-07-17，版本 20260717.9）

### 后续决策与修复状态（2026-07-17.11）

- 已修复 PRD-INST-001：安装和卸载脚本彻底移除 firewalld 自动放行、删除端口与 reload；`--purge` 不再接触 firewalld。
- 已修复预编译选择问题：从含多个 `dist` 目录的源码树执行安装器时，明确选择最新版本，不再误装最早的旧包。
- 已修复 PRD-FW-002：自动探测不再回退到原生 nftables，显式指定 `nft`/`nftables` 会拒绝启动；遗留 nft 后端的新增、删除、清空和恢复也全部拒绝执行。iptables-nft 兼容层继续支持，规则助手的 nft 命令生成/解读不受影响。
- 用户决定暂不处理 SEC-TRANSPORT-001（默认 HTTP/Token 传输风险）。
- firewalld 命令生成与解读入口按要求保留，它们只生成/解释文本，不执行命令。

### 上线结论

当前 Docker IPv4 白名单规则在用户提供的实机输出中已经正确命中：`192.168.220.1` 的 `ACCEPT` 计数为 3，兜底 `DROP` 为 0，并且两条规则都带有 `--ctorigdstport 18080 --ctdir ORIGINAL`。这证明当前 **Linux Docker Engine + IPv4 + bridge/NAT 发布端口 + iptables/iptables-nft 后端** 场景可用。

不建议把 20260717.9 原样直接作为生产最终版。建议先处理表中的全部 P0 项，以及与你的部署方式相关的 P1 项；如果通过不可信网络访问管理页面，传输加密和认证项也必须在上线前落实。

| 优先级 | 编号 | 问题 | 建议 |
|---|---|---|---|
| P0 | PRD-FW-001 | 启动恢复失败仍启动并显示规则已启用，可能静默失效/放开端口 | 上线前修 |
| P0 | PRD-FW-002 | 原生 nftables 写入逻辑会把普通规则同时写入 raw PREROUTING | 已在 20260717.11 修复：禁用原生 nft 写入 |
| P0 | PRD-INST-001 | `--purge` 可能删除并非安装器添加的 firewalld 端口并 reload | 已在 20260717.10 修复 |
| P1 | PRD-DKR-001 | 已停用的同类 ACCEPT/DROP 会让“一键白名单”误判为已存在 | 上线前修 |
| P1 | PRD-BKP-001 | “全部备份”漏掉 ip6tables；restore 使用 `--noflush` 不是精确恢复 | 上线前修或暂时禁用恢复 |
| P1 | SEC-BUILD-001 | 20260717.9 由 Go 1.22.2 构建，已不在官方支持线 | 重新构建发布包 |
| P1 | SEC-AUTH-001 | 默认外部监听配固定 `admin/admin123`，没有强制改密 | 上线前修 |
| P1 | SEC-TRANSPORT-001 | 默认纯 HTTP，Bearer Token 存 sessionStorage | 用户决定暂不处理 |
| P1 | SEC-DATA-001 | `users.json` 以 0644 保存，本地普通用户可读密码哈希 | 上线前修 |
| P1 | PRD-FW-003 | 规则同步非原子，失败时可能短暂或持续 fail-open | 建议上线前修 |
| P1 | PRD-DKR-002 | Docker 规则只区分协议+原始端口，不区分原始宿主机 IP | 多网卡同端口场景必须修 |
| P1 | PRD-ASST-001 | 助手的 DOCKER_USER“仅允许指定 IP 访问所有端口”会误伤返回流量 | 上线前修 |
| P2 | PRD-FW-004 | iptables 命令无 xtables 等锁等待、无进程超时 | 建议修 |
| P2 | PRD-IPV6-001 | 规则管理/备份的 IPv6 支持不完整 | 有 IPv6 生产流量时必须修 |
| P2 | SEC-API-001 | 多个 JSON 接口无请求体上限，HTTP 头限制也未显式收紧 | 建议修 |
| P2 | SEC-AUTH-002 | CAPTCHA 可重复用于多次猜测，且可恶意锁定 admin | 建议修 |
| P2 | SEC-WEB-001 | 无 CSP，大量 `innerHTML`/内联事件，Token 对 XSS 敏感 | 建议修 |
| P2 | PRD-OPS-001 | 无规则漂移监控、Docker/firewalld reload 后无自动校准 | 建议修 |
| P2 | PRD-OPS-002 | 缺少可审计的管理员、来源 IP、规则变更前后记录 | 建议修 |
| P2 | PRD-DATA-001 | Store 返回内部指针，并发读写存在竞态风险 | 建议修 |

### Docker 适用范围

当前做法不是“所有 Docker 部署方式都通用”，而是适用于以下条件同时成立的服务：

- Linux Docker Engine；
- IPv4；
- bridge 网络的 NAT 发布端口，例如 `-p 18080:80`；
- Docker 使用 iptables 或 iptables-nft 防火墙后端；
- `FORWARD` 确实跳转到 `DOCKER-USER`；
- 客户端访问流量确实走宿主机发布端口，而不是直接访问容器 IP。

以下情况不能直接套用：`--network host`、macvlan/ipvlan、直接路由/routed gateway、Docker 原生 nftables 后端、IPv6、Docker Desktop、rootless Docker、Swarm ingress/overlay，以及宿主机本机进程访问发布端口。每种新类型首次上线都应先看计数器验证 ACCEPT/DROP 命中。

Docker 官方说明：到达 `DOCKER-USER` 时 DNAT 已完成，要匹配原始宿主机地址/端口需要 conntrack；同时 conntrack 匹配可能带来性能损耗。参考：<https://docs.docker.com/engine/network/firewall-iptables/>。Docker 原生 nftables 后端没有 `DOCKER-USER` 链。参考：<https://docs.docker.com/engine/network/firewall-nftables/>。

### 详细发现

#### PRD-FW-001：启动恢复失败后仍对外提供“正常”服务

- Rule ID：PRD-FW-001
- Severity：High
- Location：`cmd/server/main.go:118-132`，`internal/api/handlers.go:953-960`
- Evidence：`SyncRules` 失败只记录 `WARN`，随后服务继续启动；健康检查只确认后端存在，不检查 rules.json 中每条启用规则是否真的存在于内核。
- Impact：重启时遇到 Docker 链未就绪、xtables 锁、命令失败或 firewalld 重载，JSON 仍显示“启用”，但兜底 DROP 可能不存在，Docker 发布端口会静默开放。
- Fix：启动时逐条核对；关键规则恢复失败时健康状态必须 degraded，后台有限重试并告警；Docker 白名单至少确认 ACCEPT、DROP、RETURN 和 FORWARD 跳转均存在。
- Mitigation：生产上线前每次重启后自动比对 `rules.json` 与 `iptables -S`，在监控里检查兜底 DROP 是否存在。
- False positive notes：当前用户输出证明本次规则已生效，但不能证明下次 Docker/主机重启仍会成功恢复。

#### PRD-FW-002：原生 nftables 后端会错误扩大规则作用范围

修复状态：已在 20260717.11 禁用原生 nftables 运行后端及其全部写操作；`auto` 只选择 iptables/iptables-nft。

- Rule ID：PRD-FW-002
- Severity：High
- Location：`internal/iptables/backend_nft.go:62-135`、`170-176`
- Evidence：每条 filter 规则还会被写入 `raw PREROUTING`；创建/删除/flush 多处忽略错误；`FlushChain` 会清空整个 raw PREROUTING；删除通过文本匹配寻找所有 handle。
- Impact：普通 INPUT/FORWARD/OUTPUT DROP 可能在更早的 prerouting hook 生效；清理某链可能清掉与该链无关的 raw 规则；UI 可能显示成功但某一侧失败。
- Fix：在重新设计专有 nft table、base chain priority、handle/comment 所有权和事务前，禁用原生 nftables 写操作。
- Mitigation：生产固定 `FIREWALL_BACKEND=iptables`，并在启动时验证实际后端；不要在仅有原生 nft 的机器启用规则写入。
- False positive notes：常见安装同时存在 iptables 时 auto 会优先选择 iptables；风险只在选择到 native nftables 时触发。

#### PRD-INST-001：卸载可能删除管理员原有 firewalld 端口

- Rule ID：PRD-INST-001
- Severity：High
- Location：`scripts/uninstall.sh:117-130`；安装器记录 `FIREWALL_PORT_ADDED`，但卸载器未读取它。
- Evidence：只要使用 `--remove-firewall-port`/`--purge` 就执行 `--remove-port` 和 `--reload`，没有判断该端口是否确实由安装器添加。
- Impact：如果 33801/tcp 本来就是管理员手工放行，purge 仍会移除；reload 还可能影响现有连接，违背“不随便调整防火墙规则”的要求。
- Fix：仅当 metadata 中 `FIREWALL_PORT_ADDED=true` 时才允许自动删除；否则明确跳过。reload 前展示精确 zone/port 并再次确认。
- Mitigation：修复前卸载不要使用 `--purge` 或 `--remove-firewall-port`；用默认卸载，只清程序托管的 iptables 规则。
- False positive notes：默认卸载不会触发这里；只有显式参数触发。

#### PRD-DKR-001：停用规则会让一键白名单产生错误结果

- Rule ID：PRD-DKR-001
- Severity：High
- Location：`internal/api/handlers.go:699-753`
- Evidence：检测重复 ACCEPT 和兜底 DROP 时不检查 `existing.Enabled`。停用 ACCEPT 会直接返回“已存在”；停用 DROP 会被当成有效兜底，不再创建启用的 DROP。
- Impact：界面提示“白名单已应用”，实际可能完全没有允许规则或没有兜底阻止规则，造成拒绝访问或端口开放。
- Fix：只复用启用规则；遇到停用匹配项应明确重新启用或创建新规则，并在同步后通过 `-C` 核验两条规则。
- Mitigation：创建白名单前手工删除同端口的停用 ACCEPT/DROP，而不是仅关闭。
- False positive notes：当前用户展示的两条规则均启用，因此本次不受影响。

#### PRD-BKP-001：备份和恢复语义不完整

- Rule ID：PRD-BKP-001
- Severity：High
- Location：`internal/iptables/backend_iptables.go:134-160`，`internal/api/handlers.go:468-577`
- Evidence：iptables 后端只调用 `iptables-save`，没有 `ip6tables-save`；restore 使用 `iptables-restore --noflush`，是合并/追加语义而非精确恢复；恢复后立即清空应用的托管记录；“全部备份”JSON 本身不能直接恢复。
- Impact：IPv6 规则未备份；重复恢复可能产生重复规则；恢复成功后应用失去规则所有权，后续清空/卸载无法识别这些规则。
- Fix：备份明确包含 IPv4、IPv6、managed metadata 和校验；恢复设计成事务化、有回滚、有恢复模式（replace/merge）和 out-of-band 确认；恢复后重建托管关系。
- Mitigation：修复前把界面恢复视为实验功能；生产使用系统级 `iptables-save`/`ip6tables-save` 并在控制台执行恢复。
- False positive notes：只使用 IPv4 且从不点击恢复时，备份文件仍可作为人工参考。

#### SEC-BUILD-001：发布包使用已停止支持的 Go 1.22.2

- Rule ID：SEC-BUILD-001
- Severity：High
- Location：`go.mod:3`、`Dockerfile:2,18`；`go version -m dist/.../iptables-web` 显示 `go1.22.2`。
- Evidence：Go 官方当前支持线是 1.25/1.26，1.26.5 和 1.25.12 于 2026-07-07 发布并含安全修复。参考：<https://go.dev/doc/devel/release>。
- Impact：静态链接二进制包含旧标准库，不能靠目标机升级 Go 修复 `net/http` 等标准库漏洞。
- Fix：升级 `go.mod`/Docker builder 至受支持版本，至少用 Go 1.25.12 或 1.26.5 重新构建 20260717.9 的后继包。
- Mitigation：管理端口严格限制到可信管理网，尽快替换二进制。
- False positive notes：项目没有第三方 Go 模块，风险主要来自编译器/标准库，不是依赖树。

#### SEC-AUTH-001：固定默认管理员凭据暴露在外部监听地址

- Rule ID：SEC-AUTH-001
- Severity：High
- Location：`cmd/server/main.go:33-38`，`internal/store/userstore.go:64-115`，`scripts/install-binary.sh:279-295`
- Evidence：默认监听 `0.0.0.0:33801`；首次启动固定创建 `admin/admin123`；没有首次登录强制改密标记。
- Impact：端口一旦被 firewalld/安全组放开，扫描者可直接使用公开默认凭据获得完整防火墙管理权限。
- Fix：安装时生成随机一次性密码或要求显式初始密码；首次登录必须改密后才能执行规则写操作。
- Mitigation：首次启动前只允许单一管理 IP，立即改密；保持 `AUTH_ENABLED=true`。
- False positive notes：如果现有 users.json 已经改密，升级不会重置正常管理员密码；风险主要是全新安装或空数据文件。

#### SEC-TRANSPORT-001：管理会话默认通过明文 HTTP 传输

- Rule ID：SEC-TRANSPORT-001
- Severity：High
- Location：`scripts/install-binary.sh:283-289`，`web/js/api.js:11-20`，`web/login.html:428-431`
- Evidence：安装器输出 `http://`；Bearer Token 存储于 sessionStorage 并随请求头发送；程序无 TLS。
- Impact：同网段监听、恶意网关或代理可窃取用户名、密码和会话 Token，随后修改防火墙。
- Fix：生产默认放到 HTTPS 反向代理后，或提供内建 TLS；会话优先改为 Secure/HttpOnly/SameSite Cookie。
- Mitigation：只能通过 VPN/可信管理 VLAN 访问，禁止跨不可信网络直接用 HTTP。
- False positive notes：完全隔离且可信的管理网络可降低风险，但不能消除终端或网关被攻陷的情况。

#### SEC-DATA-001：用户密码哈希文件权限过宽

- Rule ID：SEC-DATA-001
- Severity：High
- Location：`internal/store/userstore.go:407-420`
- Evidence：目录创建为 0755，临时用户文件写入模式为 0644，rename 后 users.json 保持 world-readable。
- Impact：宿主机任意普通用户可读取 PBKDF2 密码哈希并离线猜解；用户名和角色也泄露。
- Fix：目录 0700、users.json/tmp 0600；启动时主动修复旧权限；原子写后 fsync 目录。
- Mitigation：立即人工执行 `chmod 700 /var/lib/iptables-web && chmod 600 /var/lib/iptables-web/users.json`。
- False positive notes：如果上层目录已有更严格 ACL/权限，实际暴露面会缩小；默认脚本创建目录未设置该限制。

#### PRD-FW-003：同步规则不是原子操作，也没有应用所有权标记

- Rule ID：PRD-FW-003
- Severity：High
- Location：`internal/iptables/executor.go:151-188`，`internal/iptables/backend_iptables.go:65-101`
- Evidence：先逐条删除所有托管规则，再逐条添加；中途失败直接返回；规则没有 `-m comment --comment iptables-web:<id>`，删除只凭完整 spec。
- Impact：重排/编辑期间可能出现短暂开放窗口；中途失败可能只留下部分规则；与管理员手工创建的完全相同规则可能被应用删除。
- Fix：建立专用应用子链并用 comment 标识所有权；使用 `iptables-restore` 单事务替换该专用链；提交后逐条验证。
- Mitigation：低峰期变更，保留带外控制台，变更后立即核对计数器和 `iptables -S`。
- False positive notes：正常无竞争、命令全部成功时窗口通常很短，但生产安全边界不应依赖该假设。

#### PRD-DKR-002：同一宿主机端口绑定到不同 IP 时会互相影响

- Rule ID：PRD-DKR-002
- Severity：High（多网卡/多地址同端口）；否则 Medium
- Location：`internal/api/handlers.go:674-678`，`internal/iptables/backend_iptables.go:221-225`
- Evidence：UI 请求包含 `HostIP`，但规则只保存 `OriginalDPort`；生成的 spec 只有 `--ctorigdstport`，没有 `--ctorigdst <宿主机IP>`。
- Impact：例如 `10.0.0.1:18080` 与 `192.168.1.1:18080` 分别映射不同服务时，对一个映射创建 DROP 会同时限制另一个映射。
- Fix：模型增加 original destination IP，并生成 `--ctorigdst IP --ctorigdstport PORT --ctdir ORIGINAL`；UI 将 host IP 纳入规则唯一键。
- Mitigation：修复前避免在同一宿主机不同 IP 上复用相同协议/宿主机端口。
- False positive notes：当前 `0.0.0.0:18080` 的单一映射不受此问题影响。

#### PRD-ASST-001：DOCKER_USER 的无端口白名单命令会拦截返回流量

- Rule ID：PRD-ASST-001
- Severity：High
- Location：`internal/api/assistant.go:174-188,249-258`
- Evidence：`allow_ip` 场景不带 port，因此 DOCKER_USER 后处理只在 `port != ""` 时增加 `--ctdir ORIGINAL`；生成结果是“允许来源后 DROP 全部”。返回包的来源是容器，不是允许的客户端，会命中 DROP。
- Impact：执行助手生成的命令后可能导致所有 Docker 发布服务超时，重现此前类似故障。
- Fix：禁止 DOCKER_USER 使用无端口 blanket whitelist，或对 ACCEPT/DROP 明确加 conntrack direction/state 并生成恢复命令；增加命令快照测试。
- Mitigation：生产不要执行 DOCKER_USER + “仅允许指定 IP 访问所有端口”生成结果；只用经过验证的“IP + 原始宿主机端口”场景。
- False positive notes：INPUT 链不是同一个返回方向问题，但该场景仍会影响主机全部入站流量，必须人工审核。

#### PRD-FW-004：iptables/nft 子进程无锁等待和超时

- Rule ID：PRD-FW-004
- Severity：Medium
- Location：`internal/iptables/backend_iptables.go:55-165`、`internal/iptables/backend_nft.go` 多处 `exec.Command`
- Evidence：iptables 修改未使用 `-w/--wait`；命令未使用 `exec.CommandContext`；HTTP TimeoutHandler 不会自动杀死已经启动的子进程。
- Impact：Docker/firewalld 同时改规则时容易报 xtables lock；挂住的命令会长期占用 mutation mutex，后续所有写操作卡住。
- Fix：iptables 使用有限 `--wait`；所有外部命令设置 context deadline；区分锁冲突并重试。
- Mitigation：避免在 Docker 大量创建容器或 firewalld reload 时同时修改规则。
- False positive notes：空闲测试机上通常不会触发。

#### PRD-IPV6-001：IPv6 仅部分可见，不能称为完整管理/备份

- Rule ID：PRD-IPV6-001
- Severity：Medium；生产暴露 IPv6 时为 High
- Location：`internal/model/rule.go:104-140` 接受 IPv6；`internal/iptables/backend_iptables.go` 始终调用 `iptables`；Docker UI 明确只读；备份不调用 ip6tables-save。
- Evidence：模型能接受 IPv6 source/dest，但 iptables backend 没有按地址族选择 ip6tables。
- Impact：通用规则创建 IPv6 会失败；IPv6 Docker 发布端口不受界面白名单保护；完整备份漏项。
- Fix：IPv4/IPv6 独立后端与规则存储，或在所有写入口明确拒绝 IPv6 并把功能标记为 IPv4-only。
- Mitigation：生产未完善前在系统外维护 ip6tables/firewalld IPv6 策略，并单独审计 IPv6 暴露面。
- False positive notes：禁用 IPv6 且 Docker 只发布 IPv4 时不影响当前业务。

#### SEC-API-001：请求体与 HTTP 资源限制不完整

- Rule ID：SEC-API-001
- Severity：Medium
- Location：`internal/api/auth.go:39-47`、`internal/api/users.go`、`internal/api/assistant.go:90-138`、`internal/api/handlers.go:75-271`；`cmd/server/main.go:140-146`
- Evidence：多数 JSON handler 直接 Decode，无 MaxBytesReader；Server 未显式设置 ReadHeaderTimeout/MaxHeaderBytes。
- Impact：登录接口是公开端点，大 JSON 字符串可导致内存和 CPU 压力。
- Fix：统一 JSON decode helper（例如 64KiB、DisallowUnknownFields、单 JSON 值）；设置 ReadHeaderTimeout 和合理 MaxHeaderBytes。
- Mitigation：由反向代理限制 request body/header 和连接速率。
- False positive notes：已有 ReadTimeout 15 秒，能缓解慢速请求但不能限制内存分配。

#### SEC-AUTH-002：验证码复用与账号锁定可被滥用

- Rule ID：SEC-AUTH-002
- Severity：Medium
- Location：`internal/api/auth.go:55-80`，`internal/store/userstore.go:351-398`
- Evidence：CAPTCHA 仅登录成功后消费；失败 5 次按用户名锁定 15 分钟。
- Impact：解出一次验证码可连续猜 5 次；攻击者也可持续锁定已知 admin 用户，阻止管理员处理防火墙事故。
- Fix：每次登录尝试都消费 CAPTCHA；限速同时按账户+来源 IP；锁定策略避免无认证者永久制造管理员 DoS。
- Mitigation：反向代理/VPN 限定管理来源。
- False positive notes：全局 600 次/分钟/IP 限速存在，但阈值过高且不阻止分布式来源。

#### SEC-WEB-001：前端缺少 CSP，XSS 防御依赖人工转义

- Rule ID：SEC-WEB-001
- Severity：Medium
- Location：`web/index.html:1-65`，`web/js/components/*.js` 多处 innerHTML/inline onclick，`internal/api/middleware.go:23-34`
- Evidence：没有 Content-Security-Policy；大量字符串模板写 innerHTML 和内联事件。已检查到的动态防火墙字段大多经过 escapeHtml，未确认当前可利用 XSS。
- Impact：后续任何一个漏转义字段都可能窃取 sessionStorage 中的管理员 Token。
- Fix：改用 addEventListener/textContent/DOM 创建节点；移除内联事件后设置严格 CSP；会话改 HttpOnly Cookie。
- Mitigation：限制管理网来源、缩短会话、避免共享浏览器环境。
- False positive notes：本次没有证明现有字段可直接触发 XSS，因此定为防御缺口而非已证实漏洞。

#### PRD-OPS-001：没有持续规则漂移检测或自动校准

- Rule ID：PRD-OPS-001
- Severity：Medium
- Location：`cmd/server/main.go:118-132` 仅启动同步；`internal/api/handlers.go:618-630` 只检查链和跳转。
- Evidence：Docker/firewalld reload、管理员手工改规则后，程序不会周期核对每条托管规则。
- Impact：页面长期显示 enabled，但内核规则可能已被删除、改序或重复。
- Fix：只读 drift detector + 明确告警；经管理员确认或安全策略允许时再自动修复；Docker daemon restart 后触发校准。
- Mitigation：监控 `iptables-save` 哈希和关键规则计数器，变更后重启 iptables-web 触发同步并复核。
- False positive notes：Docker 通常会保留 DOCKER-USER 用户规则，但不应把所有版本/后端/reload 行为当作保证。

#### PRD-OPS-002：缺少防火墙变更审计日志

- Rule ID：PRD-OPS-002
- Severity：Medium
- Location：`internal/api/middleware.go:38-44`
- Evidence：日志只有 method/path/status/duration，没有认证用户、来源 IP、规则 ID、变更前后、执行结果摘要。
- Impact：生产事故后无法回答“谁在何时放开/阻断了哪个端口”。
- Fix：结构化、追加式审计日志；记录 actor、remote IP、request ID、action、rule diff、kernel result，且不记录密码/Token。
- Mitigation：反向代理访问日志和定期 rules.json/iptables-save 快照。
- False positive notes：systemd journal 能证明请求发生，但不足以还原规则内容和责任主体。

#### PRD-DATA-001：规则 Store 对外返回内部指针

- Rule ID：PRD-DATA-001
- Severity：Medium
- Location：`internal/store/jsonstore.go:77-115,256-263`
- Evidence：List/Get/All 只复制 slice，不深拷贝 Rule；锁释放后 JSON 编码可与重排/更新同时访问同一对象。
- Impact：并发查看和修改时可能产生数据竞态、响应字段不一致。
- Fix：Store 边界统一深拷贝；增加并发 API race test。
- Mitigation：管理端只由少量管理员使用可降低触发概率。
- False positive notes：当前 race 单测通过，但覆盖率未包含真实并发 HTTP 读写场景。

### 测试与发布包核验

本轮只运行了不会写防火墙的检查：

```text
go test -race ./...               通过
go vet ./...                      通过
go test -cover ./...              通过
node scripts/ui-logic-test.js     通过
bash -n scripts/*.sh              通过
verify-package 20260717.9         通过（未启动服务、未执行防火墙命令）
```

覆盖率：`cmd/server 30.3%`、`internal/api 32.4%`、`internal/iptables 19.7%`、`internal/store 39.3%`。最关键的真实内核链路、Docker/firewalld 重载、恢复、卸载和失败回滚没有自动集成测试，因此“单测通过”不能作为生产防火墙正确性的充分证据。

---

## 历史审计（2026-05-28）

审计日期：2026-05-28

> 本文是 2026-05-28 的历史审计快照，正文中的代码行号和“当前”描述不保证适用于后续版本。已修复状态以本文结论区的记录为准；部署当前版本请阅读 [安全模型](docs/security.md)、[配置参考](docs/configuration.md) 和 [运维手册](docs/operations.md)，并重新验证尚未关闭的风险。

## 结论

当前项目基础功能可运行，规则输入有模型校验，后端执行系统命令时主要使用 `exec.Command` 参数数组，未发现明显 shell 注入路径。主要风险集中在认证授权边界、默认凭据、密码哈希、恢复接口权限过大、请求体限制、以及 nftables/Docker 场景下的规则生效可观测性。

2026-05-28 修复状态：

- 已修复：规则写操作、排序、备份、恢复接口改为管理员权限。
- 已修复：密码哈希从自定义 salted SHA-256 升级为 PBKDF2-SHA256，并兼容旧哈希登录后自动迁移。
- 已修复：恢复接口增加管理员权限、请求体大小限制、恢复前语法校验。
- 未修复：固定默认管理员密码。用户确认部署后自行修改密码。

验证命令：

```bash
GOCACHE=/tmp/go-build-cache go test ./...
GOCACHE=/tmp/go-build-cache go build -buildvcs=false ./cmd/server
```

两项均通过。`govulncheck` 当前环境未安装，未完成依赖漏洞扫描。

## 高风险

### 1. 普通登录用户可以修改防火墙规则

位置：

- `internal/api/router.go:35`
- `internal/api/router.go:72`
- `internal/api/router.go:83`
- `internal/api/router.go:90`
- `internal/api/router.go:135`
- `internal/api/router.go:142`

代码中只对用户管理的创建、修改、删除加了 `adminRequired()`，但规则创建、修改、删除、启停、排序、备份、恢复都只是“已登录即可访问”。如果系统存在 `role=user` 的普通用户，该用户仍可改变主机防火墙。

影响：

- 普通用户可放开管理端口或业务端口。
- 普通用户可插入 `DROP`/`REJECT` 规则造成服务不可用。
- 普通用户可恢复任意规则集，影响范围超过本应用创建的规则。

建议：

- 将规则写操作、排序、启停、删除、系统恢复全部改为 admin only。
- 可保留普通用户只读查看规则、链、Docker 端口映射。
- 前端也要隐藏普通用户的写操作按钮，但后端鉴权必须作为最终边界。

### 2. 默认管理员密码是公开固定值

位置：

- `internal/store/userstore.go:64`
- `internal/store/userstore.go:87`
- `internal/store/userstore.go:108`
- `README.md:257`

首次启动会创建 `admin/admin123`。如果部署到云服务器且管理端口短时间暴露，存在被撞库或自动化扫描登录的风险。

建议：

- 安装脚本首次部署时强制生成随机管理员密码，写入 root-only 文件并打印一次提示。
- 或要求通过环境变量设置初始管理员密码，缺失时拒绝启动。
- 登录后必须强制修改初始密码。
- 不要在 README 中保留生产默认密码作为推荐路径。

### 3. 密码哈希使用自定义快速 SHA-256

位置：

- `internal/auth/password.go:12`
- `internal/auth/password.go:46`

当前格式为随机盐 + SHA-256。虽然有盐并使用常量时间比较，但 SHA-256 对密码存储过快，用户文件泄露后离线破解成本低。

建议：

- 使用 `bcrypt`、`scrypt` 或 `argon2id`。
- 增加哈希版本标识，登录成功时可将旧 `$sha256$` 自动迁移为新格式。

### 4. 恢复接口允许写入完整防火墙规则集

位置：

- `internal/api/handlers.go:389`
- `internal/iptables/backend_iptables.go:94`
- `internal/iptables/backend_nft.go:184`

`/api/v1/system/restore` 接收文本后直接传给 `iptables-restore --noflush` 或 `nft -f -`。结合“普通用户可访问恢复接口”的问题，影响很大。即便改为 admin only，这个接口仍然是高危运维操作。

建议：

- 先加 admin only。
- 恢复前做 dry-run 或语法校验。
- UI 明确展示将影响全局防火墙，不限于本应用规则。
- 保留自动备份和回滚文件。
- 可考虑默认禁用完整恢复接口，只允许从本应用导出的备份恢复。

## 中风险

### 5. 多数 JSON 接口缺少请求体大小限制

位置：

- `internal/api/auth.go:45`
- `internal/api/handlers.go:63`
- `internal/api/handlers.go:113`
- `internal/api/handlers.go:240`
- `internal/api/users.go:53`
- `internal/api/users.go:92`
- `internal/api/users.go:163`
- `internal/api/assistant.go:92`
- `internal/api/assistant.go:125`

只有恢复接口对 `data` 字段做了 2MB 长度检查，但解码前没有全局 `http.MaxBytesReader`。其他 JSON 接口直接 decode 请求体，可能被大请求体消耗内存。

建议：

- 增加 JSON decode helper，统一使用 `http.MaxBytesReader`。
- 普通 API 可限制 64KB 或 256KB；恢复接口限制 2MB。
- 对超限返回明确的 `413 Payload Too Large`。

### 6. HTTP Server 缺少显式请求头限制

位置：

- `cmd/server/main.go:113`

已设置 `ReadTimeout`、`WriteTimeout`、`IdleTimeout`，但未设置 `ReadHeaderTimeout` 和 `MaxHeaderBytes`。

建议：

- 设置 `ReadHeaderTimeout: 5 * time.Second`。
- 设置合理的 `MaxHeaderBytes`，例如 16KB 或 32KB。

### 7. 前端 Token 存在 sessionStorage 中

位置：

- `web/login.html:428`
- `web/js/api.js:11`

Token 存在 `sessionStorage`，任何前端 XSS 都可以读取。当前未发现明确的未转义用户输入直出 XSS，但项目大量使用 `innerHTML` 和内联事件，长期维护中风险较高。

建议：

- 更强方案：改为 `HttpOnly + SameSite` Cookie 会话。
- 若继续使用 Bearer Token，必须降低 XSS 面：减少 `innerHTML`，移除内联事件，增加 CSP。

### 8. CAPTCHA 可在多次错误密码中复用

位置：

- `internal/api/auth.go:55`
- `internal/api/auth.go:78`
- `internal/store/userstore.go:313`

验证码只在登录成功后消费。攻击者只要解出一次 CAPTCHA，就可以在有效期内对同一用户名多次尝试密码，直到触发账号锁定。

建议：

- 每次登录尝试都消费 CAPTCHA。
- 或对 CAPTCHA 失败、密码失败都记录统一的限速维度。

### 9. nftables raw PREROUTING 失败被静默忽略

位置：

- `internal/iptables/backend_nft.go:91`
- `internal/iptables/backend_nft.go:96`
- `internal/iptables/backend_nft.go:105`
- `internal/iptables/backend_nft.go:116`

添加 Docker 端口相关规则时，filter 规则失败会返回错误，但 raw PREROUTING 规则失败只是 `continue`。删除和 flush 中也有多处忽略错误。这会导致 UI 显示规则已添加，但外部 Docker DNAT 前流量可能没有按预期被拦截。

建议：

- 对 raw PREROUTING 添加失败至少返回 warning，并在规则详情中展示“预 DNAT 规则未生效”。
- 删除失败、flush 失败应记录日志并返回可观察结果。
- 给 Docker 映射端口规则增加集成测试或 smoke test。

### 10. 运行时和镜像版本偏旧

位置：

- `go.mod:3`
- `Dockerfile:2`
- `Dockerfile:18`

项目固定 Go 1.22 和 Alpine 3.20。Go 官方发布策略是每个大版本只支持到后面两个大版本发布为止；截至 2026-05-28，Go 1.26 已发布，因此 Go 1.22 不应再作为生产构建版本。参考：<https://go.dev/doc/devel/release>

建议：

- 升级到当前受支持 Go 版本。
- 同步升级 Alpine 基础镜像。
- CI 增加 `go test`、`go vet`、`govulncheck`。

## 低风险 / 加固项

### 11. 安全响应头还不完整

位置：

- `internal/api/middleware.go`

已有 `X-Content-Type-Options`、`X-Frame-Options`，但没有 CSP、Referrer-Policy、Permissions-Policy。当前大量内联脚本和内联事件会让 CSP 落地成本较高。

建议：

- 逐步移除内联脚本/事件后添加严格 CSP。
- 增加 `Referrer-Policy: no-referrer` 或 `same-origin`。

### 12. 前端大量使用字符串模板拼 HTML

位置示例：

- `web/index.html:199`
- `web/js/components/rules-list.js:198`
- `web/js/components/system-view.js:263`
- `web/js/components/system-view.js:269`
- `web/js/components/rule-assistant.js:110`

多数动态字段有 `escapeHtml`，未发现明确的直接用户输入 XSS，但这种模式容易在后续开发中漏掉转义。

建议：

- 对用户可控字段强制走统一渲染函数。
- 对事件绑定改为 `addEventListener`，避免把数据拼进内联 `onclick`。
- 增加 ESLint 规则或简单 grep 检查，阻止新增未审查 `innerHTML`。

## 功能完整性建议

1. 角色权限应在界面和 API 文档中明确：管理员可写，普通用户只读。
2. 规则排序需要后端做风险校验：`DROP/REJECT all` 被放到最前时，应拒绝或要求二次确认。
3. Docker 端口规则建议提供“一键生成允许名单”流程：选择端口、添加多个允许 IP、自动追加末尾 DROP，并清楚展示最终顺序。
4. 备份/恢复需要显示影响范围：本应用规则 vs 全局防火墙规则。
5. 部署脚本建议输出当前监听地址、认证状态、初始账号状态，并检测 `AUTH_ENABLED=false` 时给出强警告。
6. 增加端到端测试：未登录访问 `/`、`/index.html`、API 401；普通用户不能写规则；管理员可排序并保存；Docker 端口规则生成顺序正确。

## 优先修复顺序

1. 修复规则和系统恢复接口的 admin 权限。
2. 移除固定默认密码，改首启随机密码或强制配置。
3. 替换密码哈希算法。
4. 给所有 JSON 接口加请求体大小限制。
5. 修复 nftables raw PREROUTING 失败不可见问题。
6. 升级 Go/Alpine，并加入 `govulncheck`。
7. 逐步减少前端 `innerHTML` 和内联事件，最后加 CSP。
