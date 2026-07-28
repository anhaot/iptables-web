# HTTP API

基础路径：`/api/v1`。认证开启时使用登录会话 Bearer Token，管理员才可执行规则、用户、备份和恢复变更。

成功响应：

```json
{"success":true,"data":{}}
```

失败响应：

```json
{"success":false,"error":{"code":"validation_error","message":"..."}}
```

## 健康与系统

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康状态和唯一 packet 后端 |
| GET | `/system/status` | 内核、后端、托管规则统计 |
| GET | `/system/chains?backend=packet` | 实时链列表 |
| GET | `/system/chains/{chain}/rules?backend=packet` | 实时链规则 |
| GET | `/system/audit?limit=50` | 管理员：最近变更审计 |
| GET | `/system/audit?download=1` | 管理员：导出完整审计 JSON |
| GET | `/system/rollback` | 管理员：查询最近规则变更回滚窗口 |
| POST | `/system/rollback` | 管理员：按回滚 ID 恢复变更前托管规则 |
| GET | `/docker/mappings` | Docker socket/CLI 确认的发布映射，包含 `family=ipv4|ipv6` |
| GET | `/docker/diagnostics` | 当前请求来源 IP 与只读 DOCKER-USER 链路检查 |
| POST | `/docker/whitelist` | 管理员：原子创建来源 ACCEPT 与兜底 DROP |

没有 firewalld Zone API。

## 托管规则

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/rules?backend=packet&chain=DOCKER_USER` | 登录用户 | 查询 |
| POST | `/rules` | 管理员 | 新增 |
| GET | `/rules/{id}` | 登录用户 | 详情 |
| PUT | `/rules/{id}` | 管理员 | 更新 |
| DELETE | `/rules/{id}` | 管理员 | 删除 |
| POST | `/rules/{id}/toggle` | 管理员 | 启停 |
| PUT | `/rules/reorder` | 管理员 | 重排具体链 |

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

重排请求必须包含该链全部托管规则 ID：

```json
{"backend":"packet","chain":"DOCKER_USER","rule_ids":["allow-id","drop-id"]}
```

## 备份与恢复

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/system/backup?backend=packet` | 下载完整 packet 文本 |
| GET | `/system/backup?backend=all` | 下载组合 JSON：packet + 托管记录 + 清单 |
| POST | `/system/restore?backend=packet` | 校验并恢复完整规则集 |
| DELETE | `/system/managed-rules` | 精确删除并清空所有界面托管规则 |

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

规则、Docker 白名单、完整恢复、清空托管规则、用户与密码变更都会写入追加式 JSONL 审计。记录包含请求 ID、操作者、来源地址、操作、HTTP 结果以及脱敏后的规则/用户前后差异，不记录密码或会话 Token。

每次成功改变托管规则后会保存变更前快照，并开启 10 分钟回滚窗口：

```json
{"id":"<GET /system/rollback 返回的 id>"}
```

回滚只恢复本程序托管规则，不恢复未知外部规则；成功回滚后，回滚前状态会成为新的反向回滚点。

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
| GET | `/auth/captcha` | 验证码 |
| POST | `/auth/login` | 登录 |
| POST | `/auth/logout` | 登出 |
| GET | `/auth/session` | 会话检查 |
| POST | `/auth/password` | 修改本人密码 |
| GET | `/users` | 用户列表 |
| POST | `/users` | 管理员新增用户 |
| GET/PUT/DELETE | `/users/{id}` | 查看/管理员修改/删除 |

登录和会话响应包含：

```json
{
  "username": "admin",
  "role": "admin",
  "requires_password_change": true
}
```

默认管理员、管理员新建用户以及被管理员重置密码的用户会得到 `requires_password_change=true`。该状态下只有 `/auth/session`、`/auth/password` 和 `/auth/logout` 可访问；其他受保护接口返回 HTTP 403 和错误码 `password_change_required`。本人成功修改密码后，旧会话会被撤销，必须使用新密码重新登录。
