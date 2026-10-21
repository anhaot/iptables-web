# HTTP API

基础路径：`/api/v1`。浏览器在中心端使用 Bearer 会话；中心访问 Agent 时改用每台主机独立的 `X-API-Key`。

成功响应：

```json
{"success":true,"data":{}}
```

失败响应：

```json
{"success":false,"error":{"code":"validation_error","message":"..."}}
```

远程 Agent 对 `/docker/whitelist/batch` 或 `/rules/batch-delete` 返回 404/405 时，中心统一返回 `409` 和 `error.code=agent_upgrade_required`，表示必须升级目标 Agent。不会自动重试写入或退回逐条下发。其他 HTTP 错误保留状态；浏览器也能处理旧 Agent/反向代理的纯文本或 HTML 错误，不应显示 JSON 解析异常。若成功状态返回损坏内容，应先刷新核对实际结果再决定是否重试。

## 健康与系统

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康状态和唯一 packet 后端 |
| GET | `/system/status` | 本机授权用户：内核、后端、托管规则统计 |
| GET | `/system/chains?backend=packet` | 实时链列表 |
| GET | `/system/chains/{chain}/rules?backend=packet` | 实时链规则 |
| GET | `/system/audit?limit=50` | 中心本机仅管理员：最近控制端变更审计；Agent 端由主机授权控制 |
| GET | `/system/audit?download=1` | 中心本机仅管理员：导出完整控制端审计 JSON；Agent 端由主机授权控制 |
| GET | `/system/rollback` | 本机授权用户：查询最近规则变更回滚窗口 |
| POST | `/system/rollback` | 本机授权用户：按回滚 ID 恢复变更前托管规则 |
| GET | `/docker/mappings` | Docker socket/CLI 确认的发布映射，包含 `family=ipv4|ipv6` |
| GET | `/docker/diagnostics` | 当前请求来源 IP 与只读 DOCKER-USER 链路检查 |
| POST | `/docker/whitelist` | 本机授权用户：同批创建来源 ACCEPT 与兜底 DROP，失败尝试补偿 |

没有 firewalld Zone API。

## 多主机

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/hosts` | 查询当前用户可见的已纳管主机及 `agent_last_seen_at`；POST 手工注册返回 `405` |
| GET/PUT/DELETE | `/hosts/{host_id}` | 查询/管理员修改元数据或删除注册；地址变更必须走签名申请 |
| GET | `/hosts/{host_id}/probe` | 检查目标机健康状态和延迟 |
| `*` | `/hosts/{host_id}/api/{允许路径}` | 转发到 Agent 的固定规则、系统及 Docker API |
| POST | `/hosts/batch/rules` | 向最多 100 台已授权主机独立创建同一条规则 |
| POST | `/agent-enrollments/register` | Agent 公开提交签名申请；仅此方法无需中心会话 |
| GET | `/agent-enrollments` | 管理员列出待确认申请，不含凭据和公钥 |
| POST | `/agent-enrollments/approve` | 管理员单个或批量确认，最多 100 台；HTTPS 私有 CA 可按 Agent ID 同时提交 |
| POST | `/agent-enrollments/reject` | 管理员单个或批量拒绝，24 小时内隐藏 |

申请由 Ed25519 身份签名，并被固定到请求来源 IP；中心审批时最多并发回连 5 台 Agent 验证凭据。HTTPS 私有 CA 审批示例为 `{"ids":["<agent_id>"],"ca_pem_by_id":{"<agent_id>":"-----BEGIN CERTIFICATE-----..."}}`。证书必须包含来源内网 IP 的 IP SAN。批准后同一签名申请会更新 `agent_last_seen_at`，内存立即可见并限制为每台每分钟最多落盘一次。同地址凭据轮换复用已有 CA；地址变化重新审批时保留已有名称、启停状态和 CA。远程主机响应不会包含 Agent Key、密文或公钥。管理员可访问全部主机；普通用户可以通过 `host_ids` 逐台授权，也可以通过 `host_groups` 授权整个主机组，两者取并集。内置 ID `local` 表示中心本机防火墙，不属于远程主机组，必须逐台勾选。组权限按当前主机的 `group` 动态解析，并自动覆盖以后加入该组的主机。普通用户对授权主机拥有完整的规则、Docker、备份、恢复、Agent 防火墙审计和回滚权限；中心本机审计还包含用户、主机与密钥管理记录，因此仅管理员可读。未授权远程主机直接访问返回 `404`；未获本机授权时本机接口返回 `403`。详细部署和安全边界见[Agent 纳管与按主机授权](multi-host.md)。

批量规则下发会在任何远程写入前校验整个 `host_ids` 的格式、重复与授权。校验失败返回 400/403，不启动前面已校验主机的写入；校验通过后的远程执行仍按主机独立成功或失败，不提供跨主机回滚。

## 在线检测配置（仅中心端）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/monitoring-policy` | 已认证用户读取全局默认值 |
| PUT | `/monitoring-policy` | 管理员更新全局默认值并记录前后审计 |

```json
{"probe_interval_seconds":60,"offline_after_seconds":45}
```

`probe_interval_seconds` 为 15-3600，`offline_after_seconds` 为 30-86400，单位为秒。保存在规则文件同目录的 `monitoring-policy.json`，权限 0600。

管理员保存主机资料期间，若地址、CA、身份或凭据被另一请求更新，返回 `400 host_store_error`，需刷新后重试；不会覆盖已批准的新连接，最近已验证心跳也不会因编辑回退。

`PUT /hosts/{id}` 可另带同名字段作为逐主机覆盖，0 表示跟随全局，省略表示保留旧值。主机列表和详情响应返回覆盖值。`GET /hosts/{id}/probe` 在有效间隔内复用检测结果，并合并同一主机的并发请求；`?force=1` 可强制重新检测。成功结果增加 `checked_at`（实际检测完成时间），前端不能把读取缓存的时间误作检测时间。地址、CA 或凭据变化使旧缓存失效。停用主机的检测返回 409。

Agent 不提供 `/monitoring-policy`，中心也不得将此路径代理到远端。

## 兼容的中心 API 访问密钥

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/access-keys` | 管理员：列出本机访问密钥元数据 |
| POST | `/access-keys` | 管理员：创建并立即启用访问密钥 |
| DELETE | `/access-keys/{id}` | 管理员：立即撤销访问密钥 |

这些接口为中心 API 的脚本/外部集成保留，不用于 Agent 纳管。管理员可在“用户与权限”页创建、复制一次性明文或撤销。创建请求为 `{"name":"外部集成"}`，响应中的 `key` 只返回一次，磁盘仅保存其单向哈希；创建和撤销都不需要重启服务。

中心访问密钥按管理员身份工作，拥有中心本机、全部远程主机、用户、主机、备份恢复和密钥管理能力；当前没有为外部密钥划分只读或单主机 scope。调用方应把它视为高权限凭据，通过请求头 `X-API-Key` 使用，禁止放入 URL、仓库、配置文件、日志或命令历史。为每个集成单独创建密钥，停止使用后立即撤销。

环境变量 `API_KEY` 仅为旧部署兼容保留，不支持动态撤销且容易落入进程环境或配置文件；安装器会拒绝非空 `API_KEY`。新部署只使用页面/API 创建的动态密钥。

## 托管规则

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/rules?backend=packet&chain=DOCKER_USER` | 管理员或本机授权用户；Agent 由主机授权控制 | 查询 |
| POST | `/rules` | 管理员或本机授权用户 | 新增 |
| GET | `/rules/{id}` | 管理员或本机授权用户；Agent 由主机授权控制 | 详情 |
| PUT | `/rules/{id}` | 管理员或本机授权用户 | 更新 |
| DELETE | `/rules/{id}` | 管理员或本机授权用户 | 删除 |
| POST | `/rules/{id}/toggle` | 管理员或本机授权用户 | 启停 |
| PUT | `/rules/reorder` | 管理员或本机授权用户 | 重排具体链 |

规则示例：

```json
{
  "backend": "packet",
  "chain": "DOCKER_USER",
  "action": "ACCEPT",
  "protocol": "tcp",
  "source": "192.168.22.1",
  "dest": "",
  "dport": "",
  "original_dest": "10.0.0.5",
  "original_dport": "18080",
  "sport": "",
  "in_iface": "",
  "out_iface": "",
  "state": "",
  "position": 1,
  "enabled": true,
  "desc": "允许管理机访问 nginx"
}
```

合法链：INPUT、FORWARD、OUTPUT、DOCKER、DOCKER_USER。合法动作：ACCEPT、DROP、REJECT、LOG、RETURN。

新增、编辑、排序和启停都会校验托管规则的安全顺序；例如启用排在对应放行规则前的兜底拒绝会返回 400 / `unsafe_order`，并恢复启停前状态。常规规则变更同步后会检查启用规则是否真实存在，核验失败不返回成功。

重排请求必须包含该链全部托管规则 ID：

```json
{"backend":"packet","chain":"DOCKER_USER","rule_ids":["allow-id","drop-id"]}
```

## 批量规则与 Docker 来源

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/rules/batch-delete` | 删除 1-1000 条托管规则；本机授权或对应远程主机授权 |
| POST | `/docker/whitelist/batch` | 为一个或多个发布端口批量追加允许来源，并复用/补齐兜底 DROP |

删除请求：

```json
{"rule_ids":["<rule-id>"],"expected_updated_at":{"<rule-id>":"2026-10-20T01:00:00Z"}}
```

`expected_updated_at` 可省略；提供时必须覆盖全部 ID，并与读取规则时的 `updated_at` 一致。不存在或被修改的规则返回 409，空/重复 ID 或数量不合法返回 400；整批预检失败没有前缀删除。成功响应 `data.removed` 为删除数量。

批量新增请求：

```json
{
  "sources":["192.168.1.10","10.20.0.0/16"],
  "mappings":[{"protocol":"tcp","host_ip":"0.0.0.0","host_port":18080,"container_name":"web","container_port":80}]
}
```

每批 1-100 个来源、1-50 个端口，组合数最多 200；IPv6 只读。已有启用来源去重，允许规则插入对应兜底拒绝之前；已有允许规则但缺失兜底时会补齐 DROP。成功结果包含 `added_sources`、`added_fallbacks`、`skipped_sources`。所有输入和最终顺序在写盘及执行前完成校验；不安全顺序返回 400，Docker 链路不可用返回 409。

批量操作共用主机规则变更锁，产生一条规则差异审计及一个最近变更回滚点。写盘失败不执行内核变更；内核失败会尝试恢复旧托管状态，并在恢复不完整时返回明确错误，不能称为跨进程或内核级 ACID 事务。不 flush 链、不删除无所有权标记的外部规则。远程调用只增加上述两个固定允许路径，要求目标 Agent 升级到支持这些路径的版本。

## 备份与恢复

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/system/backup?backend=packet` | 本机授权用户：下载完整 packet 文本 |
| GET | `/system/backup?backend=all` | 本机授权用户：下载组合 JSON：packet + 托管记录 + 清单 |
| POST | `/system/restore?backend=packet` | 本机授权用户：校验并恢复完整规则集 |
| DELETE | `/system/managed-rules` | 本机授权用户：精确删除并清空所有界面托管规则 |

Web 页面直接选择“下载全部备份”得到的 `.json` 文件，文件会作为请求体直接上传。命令行调用也可直接发送该文件：

```bash
curl -X POST -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  --data-binary @iptables-web-complete-YYYYMMDD-HHMMSS.json \
  http://127.0.0.1:33801/api/v1/system/restore?backend=packet
```

旧客户端的包装请求仍兼容：

```json
{"data":"*filter\n...\nCOMMIT\n"}
```

恢复会先校验并备份当前状态，再以替换语义应用；失败时尝试自动回滚。`backend=all` 导出的组合 JSON 可直接作为请求体上传，并会恢复 IPv4、可用时的 IPv6 以及托管规则元数据。原始 `iptables-save` 文本仍可通过旧式 `{data: string}` 请求恢复，但因为不含托管元数据，恢复后的规则不会自动归属到界面。

## 审计与限时回滚

规则、Docker 白名单、完整恢复、清空托管规则、用户、密码、安全策略、Agent 审批/拒绝、主机和中心访问密钥变更都会写入追加式 JSONL 审计。周期性 Agent 注册/心跳不会写入变更审计。记录包含请求 ID、操作者、角色、来源地址、方法、路径、操作、HTTP 结果，以及脱敏后的规则、用户、主机、访问密钥元数据和安全策略前后差异；主机差异只使用安全响应视图，访问密钥差异只有 ID、名称、创建时间。不记录密码、密码历史、会话 Token、Agent Key、中心 API Key、密文、公钥或 CA 内容。中心代理远程变更时使用受 Agent Key 保护的内部头传递已认证身份、原始来源 IP 与请求 ID，因此 Agent 审计显示实际管理员/授权用户；浏览器 Bearer Token 不会发送给 Agent。

每次成功改变托管规则后会保存变更前快照，并开启 10 分钟回滚窗口：

```json
{"id":"<GET /system/rollback 返回的 id>"}
```

常规清空、回滚和卸载只删除带本程序所有权注释的规则，不会删除同条件的无标记规则。回滚只恢复本程序托管规则，不恢复未知外部规则；成功回滚后，回滚前状态会成为新的反向回滚点。

## 规则助手

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/assistant/scenarios` | 场景列表 |
| POST | `/assistant/generate` | 生成 iptables/ip6tables/nftables/firewalld 文本 |
| POST | `/assistant/interpret` | 解读一条或多条命令 |

生成示例：

```json
{
  "scenario":"allow_ip_port",
  "backend":"all",
  "chain":"DOCKER_USER",
  "family":"ipv4",
  "port":"18080",
  "protocol":"tcp",
  "source":"192.168.22.1"
}
```

`backend` 可取 all、iptables、nftables、firewalld；firewalld 还可提交 `zone` 和 `permanent`。firewalld 只支持 INPUT 入站语义。`family` 可取 ipv4、ipv6 或空。助手不执行命令。

解读：

```json
{"command":"iptables -I INPUT 1 -p tcp --dport 33801 -j ACCEPT"}
```

## 用户与认证

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/auth/captcha` | 混合大小写字母和数字的验证码，同时返回 `case_sensitive` |
| GET | `/auth/policy` | 公开读取当前密码和验证码要求，供登录/首次改密页面展示 |
| POST | `/auth/login` | 登录 |
| POST | `/auth/logout` | 登出 |
| GET | `/auth/session` | 会话检查 |
| POST | `/auth/password` | 修改本人密码 |
| GET | `/users` | 管理员：用户列表及主机分配 |
| POST | `/users` | 管理员新增用户 |
| GET/PUT/DELETE | `/users/{id}` | 查看/管理员修改/删除 |
| POST | `/users/{id}/reset-account` | 管理员：使用已配置的默认密码重置普通用户并解除锁定 |
| POST | `/users/{id}/unlock` | 管理员：只解除普通用户或管理员的持久锁定，不修改密码 |
| GET/PUT | `/security-policy` | 管理员读取或更新登录安全策略 |

登录和会话响应包含：

```json
{
  "username": "admin",
  "role": "admin",
  "host_ids": [],
  "host_groups": [],
  "requires_password_change": true
}
```

创建或更新普通用户时可同时提交逐台 `host_ids` 与主机组 `host_groups`：

```json
{
  "username": "operator",
  "password": "Initial-password-123!",
  "role": "user",
  "host_ids": ["local", "00112233445566778899aabb"],
  "host_groups": ["production"]
}
```

管理员的 `host_ids`、`host_groups` 固定为空并表示全部主机。`local` 是中心本机防火墙的保留 ID，可像单台远程主机一样授予普通用户。服务器会校验主机、主机组的存在性和重复值，权限变更会立即作用于现有会话。主机组授权会动态包含组内当前和未来主机；中心本机和未分组主机只能逐台授权。

安全策略示例：

```json
{
  "password": {
    "min_length": 12,
    "min_uppercase": 1,
    "min_lowercase": 1,
    "min_digits": 1,
    "min_special": 1,
    "history_count": 5,
    "min_changed_characters": 4
  },
  "captcha": {
    "case_sensitive": true
  },
  "login": {
    "max_failures": 5,
    "lockout_mode": "timed",
    "lockout_minutes": 15,
    "password_max_age_days": 90,
    "default_reset_password": "Write-only-temporary-123!"
  }
}
```

最小长度范围为 1-128，各字符类型数量为 0-16，密码历史为 0-10，“至少改变字符数”不能超过最小长度。新安装默认只要求密码非空且不超过 128 字符，不要求大小写、数字、特殊字符、历史或差异字符；验证码默认不区分大小写。管理员可登录后立即提高这些要求。已有 `security-policy.json` 会保持原配置，不因升级被覆盖。`max_failures` 为 1-20；`lockout_mode` 可取 `timed` 或 `administrator`；定时锁定为 1-1440 分钟；密码有效期为 0-3650 天，0 表示不限制。`default_reset_password` 是只写字段：管理员 GET 只会看到 `default_reset_password_configured`，公开 `/auth/policy` 不返回登录锁定设置或任何默认密码信息。

安全策略修改后无需重启。密码有效期在每次登录和会话校验时动态执行；过期后只允许修改本人密码或退出。失败次数按账户累计，不因来源 IP 改变而绕过；管理员解锁模式会持久化禁用状态并撤销会话，但最后一个仍可登录的管理员只进入定时锁定，避免全部管理员永久锁死。“解锁”保持原密码，“重置账户”仅适用于普通用户并应用默认密码、解除禁用、清除失败记录、撤销全部会话及设置强制改密。删除或降级管理员前，服务器会在存储写锁内确认仍保留至少一个未被持久禁用的管理员，否则拒绝变更。磁盘只保存 PBKDF2 密码哈希；默认密码明文不会进入磁盘、日志、审计或任何响应。

默认管理员、管理员新建用户以及被管理员重置密码的用户会得到 `requires_password_change=true`。该状态下只有 `/auth/session`、`/auth/password` 和 `/auth/logout` 可访问；其他受保护接口返回 HTTP 403 和错误码 `password_change_required`。本人成功修改密码后，旧会话会被撤销，必须使用新密码重新登录。

当明确配置 `AUTH_ENABLED=false` 时，根页面直接进入管理界面，`/auth/session` 返回管理员能力及 `auth_disabled=true`，不会再要求无效的登录流程。生产环境不建议关闭认证。

## Agent API

`iptables-web-agent` 默认监听 `33802`。`GET /api/v1/health` 可公开用于进程健康检查；其他固定接口必须携带 `X-API-Key: ipwa_...`。Agent 不提供用户、认证、主机清单、中心访问密钥、助手、Web 页面或任意 URL 代理。
