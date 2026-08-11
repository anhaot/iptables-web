# 开发交接与当前状态

> 最后更新：2026-08-11。继续修改前必须先执行 `git status --short`，现有未提交和未跟踪文件属于有效成果，不得重置或丢弃。

## 已确认的产品方向

多主机架构已经从“每台目标机运行完整 iptables-web、页面全局切换主机”调整为：

- 中心端运行 `iptables-web`，负责 Web UI、登录、用户、主机清单和授权；
- 目标机只安装独立的轻量 `iptables-web-agent` 二进制，无 UI、用户和主机管理；
- 页面从“纳管概览”打开某台主机详情，不再提供全局主机选择器；主机按行展示且默认收起，展开后按需加载规则摘要；中心本机使用保留 ID `local`，计入总数，可从本机行或独立的“本机防火墙”入口进入，普通用户获明确逐台授权后也可管理；
- Agent 启动后主动向中心提交签名纳管申请，管理员可单个或批量确认并命名；普通用户可按 `host_ids` 逐台授权或按 `host_groups` 动态继承主机组，对授权主机拥有完整防火墙管理权限；
- 规则助手是所有已认证用户可用的全局只读生成/解释工具，放在侧栏，不属于任何主机详情页；
- 管理员可动态配置密码长度和字符类别、最近密码历史、与当前密码的最少差异字符数、密码有效期、连续登录失败阈值和定时/管理员解锁模式，以及验证码是否区分大小写；验证码固定包含大小写字母和数字；
- 新安装默认只要求密码非空且不超过 128 字符，验证码默认不区分大小写；已有持久化安全策略升级时保持不变，管理员可登录后提高要求；
- 管理员可设置只写的账户重置默认密码；重置普通用户会清除禁用/失败状态、撤销会话并强制用户使用默认密码登录后改密，磁盘只保存哈希；另有不修改密码的账户解锁操作，最后一个可登录管理员只会定时锁定，不会永久锁死；
- 纳管申请由 Agent 主动发起，批准后的管理流量仍由中心 HTTP(S) 回连 Agent。跨 NAT 长连接是后续能力。

iptables-web 仍只管理自己创建的 IPv4 packet 规则，通过 iptables 或 iptables-nft 兼容层写入内核，不接管 firewalld，不启用原生 nftables 写入。

## Agent 与信任建立

发布包包含 `bin/iptables-web-agent`、`install-agent.sh` 和 `uninstall-agent.sh`。目标机可用环境变量执行 `MANAGER_URL=http://中心:33801 bash install-agent.sh`，也可直接执行 `bash install-agent.sh` 逐项填写；无 `MANAGER_URL` 的终端执行会自动进入交互模式，不要求附加参数，非终端环境保持非交互并立即报错。默认监听 `0.0.0.0:33802`，无需在管理端手工填写地址或密钥。

Agent 首次启动生成 Ed25519 身份，私钥种子在 `/etc/iptables-web-agent/agent.identity`，权限 `0600`。Agent ID 来自公钥摘要；每次申请包含时间戳、nonce 和签名，允许时钟偏差 5 分钟。Agent 自动生成 `ipwa_...` 管理凭据并只把 SHA-256 写入 `/etc/iptables-web-agent/agent.key.sha256`。中心待确认队列只在内存短暂持有凭据，批准时先回连受保护状态接口验证，再由 HostStore 用 AES-GCM 加密写入 `hosts.json`。主密钥为 `hosts.key` 或稳定的 `HOST_CREDENTIAL_KEY`。

管理凭据和 Agent 私钥不得写入日志、审计、列表响应或浏览器持久存储。待确认列表也不返回公钥。Agent systemd 服务重启不得执行 cleanup；只有卸载脚本在停止服务后显式调用 `--cleanup`。

HTTP/HTTPS 由每台 Agent 的 `AGENT_PUBLIC_URL` 独立声明。中心把回连主机固定为申请的实际来源 IP，只保留声明协议与端口，防止公开注册入口造成任意 URL/SSRF；审批并发 5。HTTP 只能用于可信内网并限制只允许中心 IP；HTTPS 可由 Agent 前的反向代理提供，证书必须包含来源 IP SAN，首次审批可按 Agent 提供私有 CA，同地址 Key 轮换复用已有 CA。Agent 注册应直连中心内网 IP，不能依赖普通反向代理转发头。新增主机、更新凭据和用户授权均动态生效，不要求重启中心。

待确认队列上限 1000，10 分钟未刷新过期，Agent 默认每 15 秒重报；批准后同一签名请求同时作为 Agent 心跳。中心把最近心跳写入 `agent_last_seen_at`，内存立即更新、每台最多每分钟落盘一次；前端每 15 秒刷新，超过 45 秒未上报显示“Agent 离线”。Agent 正常上报但中心主动探测失败显示“回连异常”，两者不能混为一种状态。注册按来源 IP 限制为每分钟 30 次。中心重启会丢失待确认内存，但 Agent 会重新申请。拒绝身份隐藏 24 小时。同一已批准签名身份和相同地址可自动恢复/轮换凭据；地址改变必须重新审批。

## 请求与安全边界

```text
Agent ──Ed25519 签名申请──► 中心端待确认队列
浏览器 Bearer 会话
  └─► 中心端：管理员审批、会话刷新、host_ids/host_groups 授权、固定代理路径
        └─► X-API-Key ──► Agent：固定防火墙 API ──► 本机 iptables
```

- 浏览器 Token 不发送给 Agent；
- 中心代理远程请求时使用 Agent Key 保护的内部头传递已认证用户名、角色、原始来源 IP 和请求 ID，Agent 只在 Key 验证成功后信任并写入审计；
- Agent 路由不包含用户、认证、主机清单、中心访问密钥、助手或任意代理；
- 中心远程代理仅允许规则、链、Docker、备份、恢复、审计和回滚；
- 未分配主机不出现在普通用户列表，直接访问返回 `404`；
- 管理员自动拥有全部主机；普通用户在逐台或主机组授权主机上的读写权限完整；
- 中心本机规则、链、Docker、备份、恢复和回滚 API 由 `local` 主机授权中间件统一保护；控制端审计另含用户、主机和密钥记录，仅管理员可读。远程 Agent 的防火墙审计仍由对应主机授权控制；
- 远程 401/403 转换为 502，避免浏览器清除有效的中心会话；
- 探测调用受保护的 `/system/status`，会同时验证网络与 Key；
- `POST /agent-enrollments/register` 是唯一公开的纳管方法；列表、批准和拒绝只允许管理员；
- `POST /hosts` 已禁用，已纳管地址也不能通过普通更新任意改变；
- 批量规则最多 100 台、并发 5，不提供跨主机事务。

## 关键数据文件

中心端（默认与 `RULES_FILE` 同目录）：

| 文件 | 内容 | 权限 |
| --- | --- | --- |
| `users.json` | 用户、当前/历史密码哈希、改密时间、账户禁用状态、普通用户 `host_ids` 与 `host_groups` | `0600` |
| `security-policy.json` | 密码复杂度/有效期、历史/差异、验证码、失败锁定策略和账户重置默认密码哈希 | `0600` |
| `hosts.json` | 主机元数据、最近 Agent 心跳、AES-GCM 加密 Agent Key | `0600` |
| `hosts.key` | HostStore 32 字节主密钥 | `0600`，与 hosts.json 成对备份 |
| `rules.json` | 中心本机兼容规则 | `0600` |
| `api-keys.json` | 旧兼容中心 API Key 哈希 | `0600` |
| `audit.jsonl` / `rollback.json` | 中心本机兼容审计与回滚 | `0600` |

Agent 端：

| 文件 | 内容 | 权限 |
| --- | --- | --- |
| `/etc/iptables-web-agent/agent.key.sha256` | Agent Key 单向哈希 | `0600` |
| `/etc/iptables-web-agent/agent.identity` | Ed25519 私钥种子 | `0600` |
| `/var/lib/iptables-web-agent/rules.json` | 该主机托管规则 | `0600` |
| `/var/lib/iptables-web-agent/audit.jsonl` | 该主机审计 | `0600` |
| `/var/lib/iptables-web-agent/rollback.json` | 该主机最近回滚快照 | `0600` |

## 关键代码

- `cmd/server/main.go`：中心端组装；
- `cmd/agent/main.go`：独立 Agent 入口、配置、启动恢复和安全 HTTP 超时；
- `cmd/agent/enrollment.go`、`internal/enrollment/protocol.go`：身份、签名申请、自动凭据交换和重试；
- `internal/api/agent_router.go`：Agent 固定路由和 SHA-256 常量时间认证；
- `internal/api/enrollments.go`：公开签名注册、内存待确认队列、批量批准/拒绝和回连验证；
- `internal/api/hosts.go`：中心主机元数据、授权过滤、固定代理和批量操作；
- `internal/store/hoststore.go`：主机清单及 Agent Key AES-GCM；
- `internal/model/user.go`、`internal/model/security_policy.go`、`internal/store/userstore.go`、`internal/api/users.go`：密码策略、历史哈希、`host_ids`/`host_groups` 持久化、会话刷新和分配校验；
- `web/js/app.js`：全局页、独立本机入口、打开主机详情及心跳状态；
- `web/js/components/fleet-overview.js`：默认收起的逐行纳管概览与按需规则摘要；
- `web/js/components/host-management.js`：Agent 安装命令、待确认队列、批量审批、编辑和检测；
- `web/js/components/system-view.js`：登录安全策略、用户按主机/主机组分配及主机备份/审计；
- `scripts/install-agent.sh`、`scripts/uninstall-agent.sh`：轻量安装和卸载。

前端源码必须同步 `web/` 与 `assets/web/`，并执行 `diff -qr web assets/web`。

## API 与权限重点

- `/api/v1/agent-enrollments/register`：Agent 无会话签名申请；其余 enrollment 接口仅管理员；
- `/api/v1/hosts`：只列出有权看到的已纳管主机，不能手工 POST 新增；
- 主机列表的 `agent_last_seen_at` 来自已验证签名心跳；访问密钥、密文和公钥仍不返回；
- `/api/v1/hosts/{id}`：管理员可改名称、分组、启停和 CA，但地址变更必须由同一 Agent 的签名申请触发；
- `/api/v1/hosts/{id}/api/...`：管理员或通过单台/主机组分配到该主机的普通用户可调用固定接口；
- `/api/v1/users`：仅管理员可列出或修改，请求/响应包含 `host_ids` 与 `host_groups`，`host_ids` 可含保留值 `local`；
- `/api/v1/users/{id}/reset-account`：仅管理员使用已配置的默认密码重置普通用户、解锁并强制改密；
- `/api/v1/users/{id}/unlock`：仅管理员解除普通用户或管理员的持久锁定，不修改密码；
- `/api/v1/auth/session`：包含当前用户 `host_ids` 与 `host_groups`，权限变更通过 UserStore 会话刷新立即生效；
- `/api/v1/auth/policy`：公开只读密码/验证码要求且不暴露锁定/默认密码信息；`/api/v1/security-policy`：仅管理员读取和更新，返回默认密码是否已配置但不返回哈希或明文；
- 删除主机后清理用户分配，清理写盘失败不会把已完成的主机删除错误报告为失败；
- Agent `/api/v1/health` 公开，其余固定接口必须提供正确 `X-API-Key`。

2026-08-09 深度审查修复后：中心本机审计改为管理员专属，远程 Agent 防火墙审计仍按主机授权；Agent 审批/拒绝进入变更审计但周期心跳不写审计；验证码改为原子校验并消费；新增独立账户解锁且最后一个可登录管理员只定时锁定。HTTPS 纳管继续固定来源 IP，首次审批可按 Agent 提供私有 CA，同地址 Key 轮换及地址变更保留已有 CA/启停/名称，证书要求来源 IP SAN。中心安装器保留外部 `HOST_CREDENTIAL_KEY`，Agent 安装器把中心 CA 复制到固定配置目录。中心“用户与权限”页新增外部 API 访问密钥的一次性明文创建/撤销；Agent 仍无 UI。纳管概览和 Agent 清单每分钟刷新受保护回连探测，认证关闭时隐藏无效的改密/退出入口。

## 验证要求

完成功能后至少运行：

```bash
gofmt -w <修改的 Go 文件>
go test ./...
go test -race ./...
go vet ./...
node scripts/ui-logic-test.js
bash -n scripts/*.sh
docker compose config
docker compose -f docker-compose.release.yml config
bash scripts/integration-smoke.sh
git diff --check
diff -qr web assets/web
```

还必须在 `1440×1000` 桌面浏览器中验证：纳管概览、Agent 登记、打开/返回主机详情、普通用户只见授权主机、管理员用户分配表单，以及控制台无错误。移动端不在当前验收范围。

2026-08-05 主动申请版本已重新通过 Go 普通测试、竞态测试、`go vet`、前端逻辑测试、全部 shell 语法、Compose 配置、前端双目录对比、`git diff --check` 和双二进制构建。真实联调启动了一个独立中心和三台 DEV Agent：Agent 无需中心手填即自动进入待确认队列；两台 API 批量批准和一台浏览器批量批准均成功；申请地址被固定为来源 IP；批准后探测、固定代理、Agent 重启免重复审批、中心重启自动重报均正常；所有临时数据中无 `ipwa_` 明文。还验证了 Agent 专用 `--cleanup` 清空自己的托管记录，以及 1440×1000 页面待确认、批量对话框、批准、地址只读编辑和三台在线状态，最终浏览器控制台为 0 错误/0 警告。发布包 `20260805-active-enrollment` 已完成离线校验。

同日后续增加已批准 Agent 心跳与 45 秒离线判定，界面区分离线和中心回连异常；恢复管理员专用的中心“本机防火墙”入口；安装脚本同时支持环境变量、无参数自动终端交互、显式 `--interactive`/`--non-interactive`。随后按产品反馈移除首页独立本机大卡片，把本机作为普通纳管主机卡片计入总数和在线数；本机详情仅保留页面导航标签，不再展示返回按钮、主机身份和“本地直连”上下文行。

本机纳管卡片调整后重新通过 Go 普通测试、竞态测试、`go vet`、前端语法和逻辑测试、全部 shell 语法、Compose 配置、前端双目录对比及 `git diff --check`；1440×1000 浏览器验证了本机卡片、总数/在线数、本机页签和 0 错误/0 警告。发布包 `20260805-local-managed-node` 已完成双二进制构建、SHA-256 和离线内容校验。

登录安全策略、混合验证码和主机组授权版本重新通过 Go 普通测试、完整竞态测试、`go vet`、前端语法与逻辑测试、全部 shell 语法、Compose 配置、前端双目录对比、`git diff --check` 和双二进制构建。1440×1000 浏览器验证了安全策略表单、主机组与单台主机组合授权、混合大小写输入保持原样，并确认管理页和登录页均为 0 错误/0 警告；公开策略和验证码接口、管理员策略接口、响应不泄露密码历史、策略文件 `0600` 也已用真实服务验证。发布包 `20260805-security-groups` 已完成双二进制构建、SHA-256 和离线内容校验。

本机授权、折叠式纳管列表和账户锁定版本进一步把中心本机统一为可逐台分配的 `local` 主机，把规则助手移到全局侧栏，并加入登录失败阈值、定时/管理员锁定、密码有效期、只写默认密码安全重置和强制改密。完整 Go 测试、竞态测试、`go vet`、前端逻辑/语法、Shell、Compose、双目录和补丁检查均通过。真实 API 验证了 `local` 分配、默认密码重置、公开/管理员策略分离、明文扫描无结果及数据文件 `0600`；1440×1000 浏览器验证了管理员安全策略、全局规则助手、默认收起的主机行，以及普通用户只显示并可进入已授权本机，控制台 0 错误/0 警告。期间发现并修复 CSS `display:flex` 覆盖 `hidden` 导致普通用户仍看见管理员链接的问题，并加入前端回归断言。发布包 `20260805-host-auth-lockout` 已完成双二进制构建、SHA-256 和离线内容校验。

2026-08-09 根据实际桌面页面审查重做纳管概览的主机展开态：展开后明确展示 Agent 签名身份、接入协议、连接状态与心跳、加密凭据/CA、纳管时间，并把规则摘要和进入主机配置的操作分成清晰区块；离线时仍可查看主机资料，只禁用需要回连的入口。同步提高登录安全策略说明文字的可读性，并避免向当前管理员显示自删除操作。前端源码继续保持 `web/` 与 `assets/web/` 同步。

2026-08-09 部署链路审计后统一改为 systemd 事务安装：中心和 Agent 都使用权限为 `0600` 的 EnvironmentFile、原子二进制替换、`systemd-analyze verify`、enable/restart、15 秒健康检查，失败时恢复旧二进制/unit/env 和原有运行状态；不再在 systemd 失败时直接后台运行。中心安装器拒绝把旧式静态 `API_KEY` 明文落盘。Agent 发布包根目录二进制查找、轮换失败时 key hash 恢复也已修复。仓库新增可审计的 `deploy/systemd/` 模板，以及使用预编译二进制的 `Dockerfile.release`/`docker-compose.release.yml`；源码和容器构建默认限制 Go 并发，Compose 默认限制 1 CPU、512 MiB。部署文档现覆盖发布包、源码、手动 systemd、Agent、源码/发布包容器、验收、升级和回滚。

同次部署验收实际启动了独立 `dev` 中心和 Agent systemd 服务：两者安装、enable、active、健康检查、0600/0700 权限均通过；再故意升级到已占用端口，中心和 Agent 均拒绝并恢复旧端口、配置和运行状态，随后测试服务/数据已卸载。发布包运行时容器也以 host network、受限能力和资源上限完成健康/权限验证。容器健康脚本改为调用应用健康接口，由应用按当前真实或 dev 后端核验，避免 DEV_MODE 仍执行宿主机 iptables 而误报不健康。

最终测试中心已更新为镜像 `sha256:da676544a1bf2ec22398b649095848dd175ac1bdbe651f6af72b2a669138d1b8`，容器 `iptables-web-test` 使用 host network、1 CPU/512 MiB、cap-drop ALL、no-new-privileges 和原数据卷，当前 Docker health 为 healthy；两个测试 Agent 已恢复签名心跳。旧容器 `iptables-web-test-rollback-systemd-audit` 保留为停止状态回滚点。

2026-08-09 深度审查修复版本重新通过完整 Go 测试、竞态测试、`go vet`、双二进制构建、前端逻辑和全量 JavaScript 语法检查、Shell 语法、两套 Compose 配置、前端双目录对比、格式与补丁检查。新增回归覆盖控制端审计权限、验证码一次性消费、管理员解锁/最后管理员保护、HTTPS 私有 CA 首次审批及同地址 Key 轮换、脱敏主机/访问密钥审计差异。1440×1000 浏览器验证了认证关闭时隐藏无效入口、中心访问密钥一次性显示/撤销、Agent 纳管页和 0 错误/0 警告；测试密钥已立即撤销，含明文的临时浏览器快照已清理。发布包 `20260809-review-fixes` 已完成双二进制、安装器 DRY_RUN、SHA-256 和离线内容校验。

2026-08-09 发布前全仓审计继续修复了规则、用户、会话、验证码、主机、审计与回滚标识生成时忽略安全随机源错误的问题；已有 Agent identity 权限无法收紧到 `0600` 时现在拒绝继续使用。新增 `scripts/integration-smoke.sh` 和 `make integration-test`，强制回环监听与 `DEV_MODE`，真实启动中心和无界面 Agent，自动验证签名申请、审批、受保护回连、远程规则 CRUD、Agent 审计、无 UI 边界以及磁盘/日志无 `ipwa_` 明文。Makefile 修复了 Shell 默认变量被 Make 吞掉和旧 `docker-compose` 命令；两套 Compose 支持通过 `.env` 覆盖非敏感运行参数，并改用读取 `LISTEN_ADDR` 的健康脚本，非默认端口也能正确探测。README 已重写项目定位、设计亮点和适用边界；部署手册扩展为内网 IP 拓扑、依赖、脚本变量、完全手动中心/Agent、Nginx HTTPS、IP SAN 私有 CA、源码/发布包容器、可靠卷备份恢复、验收、故障表和三层真实可用性说明。发布包现完整携带 `docs/images/`，离线 README 截图链接不会失效。完整普通/竞态测试、`go vet`、隔离端到端烟测、安装器 DRY_RUN、Compose 解析、源码容器实跑、文档链接和 Make 目标展开均已通过；本轮发布标识为 `20260809-release-audit`。

2026-08-11 根据 Ubuntu Agent 与麒麟中心的现场联调补充“Agent 未出现在待确认列表”分层排障：先区分主动注册 `33801` 与审批回连 `33802`，再检查服务、健康接口、过滤后的连接配置、注册日志、中心路由、监听地址和五分钟时差，禁止用清空防火墙替代网络诊断。远程 Agent 审计现在由中心在 Agent Key 认证通道内传递实际用户名、角色、原始来源 IP 和请求 ID，页面可展开查看方法、路径及脱敏前后差异；浏览器 Token 仍不离开中心。新安装默认验证码不区分大小写，密码仅要求非空且不超过 128 字符，管理员登录后可配置复杂度、历史和差异要求；已有持久化策略不自动降级。历史 `bin/`、`dist/` 二进制、解压目录与压缩包已清理；两处默认绑定 IPv6 的 HTTP 测试改为显式 IPv4，在受限构建环境中不再 panic。本轮已通过普通/竞态 Go 测试、`go vet`、前端逻辑与语法、Shell、两套 Compose、隔离端到端烟测、双前端目录和补丁检查；1440×1000 浏览器验证了默认安全策略、全宽审计详情及 0 错误/0 警告。

2026-08-11 发布前完成正式文档与当前实现的逐项对表：统一控制平面、治理闭环、受认证操作者和多主机信任边界等术语；明确 Agent 每 15 秒签名心跳、页面每 15 秒刷新心跳视图、每台主机回连探测至多每分钟一次；修正 API 章节层级、示例格式、审计主体和 Go 工具链口径。文档不扩大现有能力边界，所有部署命令、默认策略、接口路径和持久化说明均以当前代码及脚本为准。

2026-08-11 Release 内容审计确认仓库 `scripts/` 中各入口均有明确职责和调用方，不删除会影响安装、构建或回归验证的源码工具；面向目标机的压缩包则按最小运行集合收敛，`scripts/` 只携带安装器依赖的 `install-lib.sh` 与发布容器需要的 `healthcheck.sh`。发布侧 `verify-package.sh`、开发侧 `integration-smoke.sh`/`ui-logic-test.js`，以及缺少源码时不可用的源码版 `Dockerfile`/`docker-compose.yml` 不再进入 Release，离线验包会反向断言这些文件不存在。

## 尚未实现

- Agent 跨 NAT 长连接（当前只是主动申请，管理流量仍需中心回连）；
- mTLS、内建 TLS；
- 细粒度只读角色；
- 策略版本、灰度发布、跨主机事务或自动补偿；
- IPv6 托管规则 CRUD；
- 审计汇聚与轮转。

后续实现不能扩大 Agent/远程代理到用户、认证、访问密钥或任意 URL，也不能让凭据明文落盘或要求新增主机重启。
