# 开发交接与当前状态

> 最后更新：2026-10-21。继续修改前必须先执行 `git status --short`，现有未提交和未跟踪文件属于有效成果，不得重置或丢弃。

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

中心和 Agent 当前仅提供发布包/源码/手动 systemd 部署；Docker/Compose 部署文件、构建入口及容器专用健康脚本已移除。Docker 发布端口识别与访问控制功能继续保留。

iptables-web 仍只管理自己创建的 IPv4 packet 规则，通过 iptables 或 iptables-nft 兼容层写入内核，不接管 firewalld，不启用原生 nftables 写入。

## Agent 与信任建立

发布包包含 `bin/iptables-web-agent`、`install-agent.sh` 和 `uninstall-agent.sh`。目标机可用环境变量执行 `MANAGER_URL=http://中心:33801 bash install-agent.sh`，也可直接执行 `bash install-agent.sh` 逐项填写；无 `MANAGER_URL` 的终端执行会自动进入交互模式，不要求附加参数，非终端环境保持非交互并立即报错。默认监听 `0.0.0.0:33802`，无需在管理端手工填写地址或密钥。

Agent 首次启动生成 Ed25519 身份，私钥种子在 `/etc/iptables-web-agent/agent.identity`，权限 `0600`。Agent ID 来自公钥摘要；每次申请包含时间戳、nonce 和签名，允许时钟偏差 5 分钟。Agent 自动生成 `ipwa_...` 管理凭据并只把 SHA-256 写入 `/etc/iptables-web-agent/agent.key.sha256`。中心待确认队列只在内存短暂持有凭据，批准时先回连受保护状态接口验证，再由 HostStore 用 AES-GCM 加密写入 `hosts.json`。主密钥为 `hosts.key` 或稳定的 `HOST_CREDENTIAL_KEY`。

管理凭据和 Agent 私钥不得写入日志、审计、列表响应或浏览器持久存储。待确认列表也不返回公钥。Agent systemd 服务重启不得执行 cleanup；只有卸载脚本在停止服务后显式调用 `--cleanup`。

HTTP/HTTPS 由每台 Agent 的 `AGENT_PUBLIC_URL` 独立声明。中心把回连主机固定为申请的实际来源 IP，只保留声明协议与端口，防止公开注册入口造成任意 URL/SSRF；审批并发 5。HTTP 只能用于可信内网并限制只允许中心 IP；HTTPS 可由 Agent 前的反向代理提供，证书必须包含来源 IP SAN，首次审批可按 Agent 提供私有 CA，同地址 Key 轮换复用已有 CA。Agent 注册应直连中心内网 IP，不能依赖普通反向代理转发头。新增主机、更新凭据和用户授权均动态生效，不要求重启中心。

待确认队列上限 1000，10 分钟未刷新过期，Agent 默认每 15 秒重报；批准后同一签名请求同时作为 Agent 心跳。中心把最近心跳写入 `agent_last_seen_at`，内存立即更新、每台最多每分钟落盘一次；前端每 15 秒刷新（回连间隔和离线阈值现已可配置，见下文），默认超过 45 秒未上报显示“Agent 离线”。Agent 正常上报但中心主动探测失败显示“回连异常”，两者不能混为一种状态。注册按来源 IP 限制为每分钟 30 次。中心重启会丢失待确认内存，但 Agent 会重新申请。拒绝身份隐藏 24 小时。同一已批准签名身份和相同地址可自动恢复/轮换凭据；地址改变必须重新审批。

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
| `monitoring-policy.json` | 默认回连检测间隔与心跳离线阈值 | `0600` |
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

## 当前修复与兼容性决策（2026-10-20）

- 删除、清空、回滚、卸载和启动同步均只处理带 `iptables-web:<rule-id>` 注释的规则；移除无标记规则的兼容删除与启动自动迁移。旧版无标记规则需要备份后人工核对，不得按“同条件”认领外部规则。
- 用户存储在同一写锁内保护最后一个未持久禁用的管理员，不能删除或降级；备用管理员被禁用时不算有效恢复入口，并覆盖并发降级。
- 批量下发在启动任何 goroutine 前完成整个 ID 列表的格式、去重和授权校验，避免 400/403 后部分下发；远程执行仍是逐主机独立结果。
- 强制选择 `iptables-nft`/`iptables-legacy` 时，使用对应的 IPv4、save/restore 与 IPv6 备份/恢复命令家族，工具缺失不悄悄回退到 alternatives。
- 安装器要求规范绝对路径，并区分程序专用目录与 BIN_DIR；拒绝根目录、共享系统目录、运行目录、`..`、重复/尾部斜杠及符号链接。卸载也拒绝危险路径别名。依赖 GNU coreutils 的 `realpath`。
- 清空托管规则后写盘失败，会恢复内存并尝试重建旧运行态；删除途中失败也尝试同步旧规则。
- 启停同样校验安全顺序，避免通过启用禁用 DROP 绕过新增/排序校验；普通规则变更在同步后统一核验已启用规则存在，完整组合恢复也核验托管规则。IPv4/IPv6 完整恢复命令报错时会尝试应用对应的旧备份，不能假设命令失败就没有部分表被修改。
- 当前只保留宿主机原生 systemd 部署，发布包 `scripts/` 只带 `install-lib.sh`；包含两套二进制、安装/卸载脚本、LICENSE、systemd 模板、正式 Markdown 文档及截图。验包会拒绝已移除的容器部署文件及开发侧脚本。
- 个人面试材料仅在本地保留，已加入 Git 忽略并从发布包排除，不能提交源码仓库或上传 GitHub Releases；公开文档不提供面试材料入口。

## 本轮复核补充（2026-10-20）

- PBKDF2 校验拒绝长度异常的盐和摘要，修复空摘要导致任意密码通过的问题。
- 规则文件加载使用临时结构，校验 null、空/重复 ID 和规则字段后才替换内存；保留旧 firewalld 元数据清理、旧 Docker dport 组合的启动迁移。用户文件拒绝 null、空/重复 ID、重名和未知角色；没有管理员且 admin 名称被占用时停止启动。回滚数据在执行前检查结构与规则字段。
- 完整备份与规则变更共用 mutationMu，防止读取本程序变更过程中的元数据/内核中间态；不协调外部管理程序的并发写入。
- 审批选择时清理过期申请，回连后在队列锁内重新确认申请未被拒绝、过期或更改；同内容新心跳不阻断正常审批。
- HostStore.UpdateAgentConnection 在写锁内只更新验证过的端点/CA/凭据，保留最新管理员元数据，并拒绝探测期间旧端点/CA/身份/凭据被更改的结果，避免凭据轮换或地址审批覆盖新分组、名称和禁用状态；心跳时间单调前进。
- 面试稿只保留本地，Git 忽略与发布验包共同排除；不要重新添加公开入口或放入 GitHub Release。

## 在线检测、搜索与 Docker 批量操作（本轮新增）

- `internal/model/monitoring.go`、`internal/store/monitoringstore.go`：中心 `monitoring-policy.json`（与 RULES_FILE 同目录，0600）；全局默认回连间隔 60 秒，范围 15-3600；离线阈值 45 秒，范围 30-86400。
- `/monitoring-policy` GET 允许已认证用户读取，PUT 仅管理员，并记录前后审计；Agent 不暴露、代理不转发此设置。
- 主机 `probe_interval_seconds`/`offline_after_seconds` 为 0 跟随全局，省略更新保留旧值；纳管编辑和远程主机配置入口可设置，动态生效。Agent 签名心跳仍 15 秒，UI 刷新仍 15 秒，实际自动检测可能延迟一个刷新周期。
- `internal/api/host_probe.go`：按主机缓存回连结果并合并并发请求，端点/CA/凭据变化失效；`?force=1` 手动重试。页面打开才触发自动探测，没有新增后台全时监控器。
- 纳管概览增加名称、IP/地址、组、Agent ID 搜索，仅过滤已授权清单，统计卡仍显示全部可见主机。
- Docker 按容器聚合端口；可多行追加来源并选择端口、勾选多条删除、清空某端口/某容器。确认包含范围与兜底删除风险；不明归属保留为残留策略。
- 新固定防火墙路径 `/rules/batch-delete`（POST，1-1000 条，可带 expected_updated_at 冲突检查）和 `/docker/whitelist/batch`（POST，1-100 来源、1-50 端口、最多 200 组合）。中心本机需 local 授权，远端需主机授权；旧 Agent 需升级，不能悄悄退回逐条执行。
- `internal/api/docker_batch.go` 先在临时存储完成新增规划和顺序校验，再在同一变更锁内应用；批量删除全部预检，内核失败尝试补偿。一次批次对应一次审计和最近回滚点，不承诺内核级事务。
- JSONStore 规范化仅对实际位置变化更新 UpdatedAt，避免新增批次或重载导致无关规则冲突。
- 本轮功能在隔离服务/数据验证；不以源码或包构建完成推断现有 systemd 服务已更新，不操作远程主机的真实规则。

## 关键回归文件

- 纳管搜索与“刷新状态”放在同一行；Docker 页面移除管理连接来源长提示，诊断接口字段不变。
- `web/js/api.js` 对纯文本/HTML/损坏 JSON 保留 HTTP 状态，写请求不得自动重试；异常成功响应提示先刷新核对结果，避免重复提交。
- 中心对远程两个批量接口的 404/405 返回 JSON `409 agent_upgrade_required`，没有逐条降级或重试；目标 Agent 必须单独升级，不能把中心升级等同于 Agent 已更新。
- Docker 切换主机时清除映射、规则、诊断与选择；映射读取失败清空旧映射，禁止展示其他主机的残留缓存。
- 主机详情“检测设置”并入顶部主机信息栏右侧；Docker 容器默认收起，可独立展开，端口摘要去掉重复容器标题，仅保留映射与策略说明。搜索/筛选展开匹配容器，同主机刷新保留展开状态，换主机重置；批量按钮仍在容器标题栏，折叠不改变规则操作范围。

- `internal/api/clear_managed_test.go`：Agent 清空保留无标记规则，写盘失败重建运行态。
- `internal/api/handlers_order_test.go`、`backup_test.go`：启停顺序、命令成功但规则缺失，以及恢复命令失败后的补偿。
- `internal/api/hosts_test.go`：重复/非法/未授权批次没有远程写入。
- `internal/store/userstore_test.go`：最后管理员、被禁用备用管理员及并发降级保护。
- `internal/iptables/backend_iptables_test.go`、`executor_test.go`：命令家族、所有权与规则同步。
- `internal/auth/password_test.go`：损坏 PBKDF2 哈希不能认证。
- `internal/api/enrollments_lifecycle_test.go`、`internal/store/hoststore_test.go`：过期/拒绝/变更审批与连接更新并发保护。
- `internal/store/jsonstore_test.go`、`internal/change/manager_test.go`：损坏数据拒绝、旧格式迁移兼容；`backup_test.go` 同时覆盖备份等待未完成变更。
- `scripts/install-path-test.sh`（`make script-test`）：安装和卸载的危险目录、路径别名及符号链接检查。卸载测试必须通过独立 APP_NAME、目录和命令拦截运行，不能读取真实安装元数据；卸载脚本在元数据覆盖前后分别校验目录，非法显式路径不得被元数据掩盖。

## 验证要求

完成功能后至少运行：

```bash
gofmt -w <修改的 Go 文件>
go test ./...
go test -race ./...
go vet ./...
node scripts/ui-logic-test.js
for script in scripts/*.sh; do bash -n "$script" || exit; done
for script in web/js/*.js web/js/components/*.js; do node --check "$script" || exit; done
bash scripts/install-path-test.sh
bash scripts/integration-smoke.sh
git diff --check
diff -qr web assets/web
```

发布前另运行 `VERSION=<本次版本> bash scripts/build-package.sh`，脚本会构建双二进制、生成 SHA-256 并离线验包；同时检查 Markdown 本地链接、章节锚点和源码引用。程序自身不再提供容器部署，因此不运行 Compose 验收。

还必须在 `1440×1000` 桌面浏览器中验证：纳管概览、Agent 登记、打开/返回主机详情、普通用户只见授权主机、管理员用户分配表单，以及正常操作控制台无错误。移动端不在当前验收范围。

## 既有验证与实现背景

2026-08-05 至 2026-08-11 已完成多主机主动申请、签名心跳、本机逐台授权、主机组、折叠列表、登录策略、账户解锁、私有 CA 审批、动态外部访问密钥及远程实际操作者审计。之前的测试包括 Go 普通/竞态测试、前端逻辑与桌面浏览器、隔离中心/Agent HTTP 联调，以及专用测试服务上的 systemd 安装失败回滚。完整历史在 Git 历史中保留。

历史测试环境的 PID、镜像、容器或在线状态不代表当前环境状态；继续工作时需要重新验证，不能据旧交接记录操作未知服务。

## 尚未实现

- Agent 跨 NAT 长连接（当前只是主动申请，管理流量仍需中心回连）；
- mTLS、内建 TLS；
- 细粒度只读角色；
- 策略版本、灰度发布、跨主机事务或自动补偿；
- IPv6 托管规则 CRUD；
- 审计汇聚与轮转。

后续实现不能扩大 Agent/远程代理到用户、认证、访问密钥或任意 URL，也不能让凭据明文落盘或要求新增主机重启。

## 开源整理复核（2026-10-21）

- 管理员资料编辑改用 `HostStore.UpdateMetadata`，在写锁内核对地址/CA/身份/凭据版本，拒绝旧页面覆盖新连接；同时保留最新签名心跳，新增存储回归。
- `.gitignore` 明确排除本地笔记、主机与策略运行文件、Agent 身份和常见密钥格式；个人材料继续只保留本地。
- `scripts/check-source.py` 检查公开文件边界、本地 Markdown 链接、锚点和明确源码引用，CI 与打包前执行；构建机新增 Python 3 要求，目标安装机不变。
- 发布包文档改为显式清单，不再复制所有 Markdown。公开范围与验证限制见 `docs/open-source.md`。
- 新增 `.github/workflows/ci.yml`，对源码和 PR 执行 Go 普通/竞态/vet、前端逻辑与语法、安装路径、资源同步、文档和隔离 HTTP 联调。
- 当前验证始终使用隔离数据与 no-op 后端，不操作现有 systemd 服务或真实远程规则；真实内核与发行版部署仍需专用测试机验收。

- 本轮复核包含 173 个 Go 测试入口的普通/竞态测试、vet、前端/安装路径、包内双进程联调、Gitleaks 当前内容/历史和 govulncheck；具体边界见公开复核文档。README 截图更新为隔离演示环境，Docker 映射采用浏览器演示响应，不公开真实本机容器信息。

## 正式发布补充（2026-10-21）

- `e283ebc` 更新了源码并通过 CI，但没有版本 Tag，因此不会更新旧的 GitHub Release 附件。本轮以新版本 `v0.3.0` 发布新增监控、Docker 批量操作和安全修复。
- 发布包可直接使用 `VERSION=0.3.0 bash scripts/build-package.sh` 在本地构建，不依赖 CI/CD；`main` 推送只运行检查，新 `vX.Y.Z` Tag 才触发 `.github/workflows/release.yml` 构建并创建 Release。
- 发布前验证本地双二进制与压缩包；正式附件需在 Release 工作流成功后核对版本、SHA-256 和内容。不能把源码推送成功、CI 成功或 GitHub 自动生成的 Source code 压缩包当作二进制已发布。
- 旧 Tag 和旧 Release 保留；中心与 Agent 需分别升级，中心升级不会替远程 Agent 更新二进制。仍不操作现有 systemd 服务或真实远程规则。
