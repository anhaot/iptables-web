# 运维与排障

iptables-web 运行在高权限环境。新增宽范围拒绝、恢复完整规则集、修改默认策略或清空规则前，应先备份并准备物理或带外控制台。部署参数和网络暴露要求见[部署与配置](deployment.md)。

## 日常只读检查

```bash
sudo systemctl status iptables-web --no-pager
sudo journalctl -u iptables-web -n 100 --no-pager
sudo ss -lntp | grep 33801
curl http://127.0.0.1:33801/api/v1/health
sudo iptables -nvL INPUT --line-numbers
sudo iptables -nvL FORWARD --line-numbers
sudo iptables -nvL DOCKER-USER --line-numbers
```

这些命令不会修改防火墙。

Agent 主机使用对应服务名和端口：

```bash
sudo systemctl status iptables-web-agent --no-pager
sudo journalctl -u iptables-web-agent -n 100 --no-pager
curl --fail http://127.0.0.1:33802/api/v1/health
```

## systemd 启动或升级失败

安装脚本不会退回为后台直接运行。若新版本 unit、启动或健康检查失败，会恢复安装前的二进制、unit、EnvironmentFile，以及原有 enable/active 状态。按以下顺序收集信息：

```bash
sudo systemctl status iptables-web --no-pager -l
sudo journalctl -u iptables-web -b -n 200 --no-pager
sudo systemctl cat iptables-web
sudo systemctl show iptables-web -p LoadState -p ActiveState -p SubState -p ExecMainStatus
sudo systemd-analyze verify /etc/systemd/system/iptables-web.service
sudo stat -c '%a %U:%G %n' /etc/iptables-web/iptables-web.env /var/lib/iptables-web
sudo /usr/local/bin/iptables-web --version
```

Agent 把名称替换成 `iptables-web-agent`，配置文件替换成 `/etc/iptables-web-agent/agent.env`。常见原因：

- EnvironmentFile 路径或数据目录写错；
- 数据目录不是 root 私有，或 `ProtectSystem=strict` 下未列入 `ReadWritePaths`；
- 端口已被占用；
- 指定的 iptables 后端不存在；
- Agent 私有 CA 文件移动、权限错误或中心 URL 不可达；
- 旧规则数据无法在当前运行后端恢复并核验。

只修改 EnvironmentFile 后必须重启进程：

```bash
sudo systemctl restart iptables-web
curl --fail http://127.0.0.1:33801/api/v1/health
```

新增主机、批准 Agent、修改主机 HTTPS/CA、创建或撤销动态访问密钥不需要重启。

Agent 安装器管理的中心 CA 固定为 `/etc/iptables-web-agent/manager-ca.pem`。若 Agent 心跳报证书错误，检查该文件权限、`agent.env` 的 `MANAGER_CA_FILE` 以及中心证书是否包含 `MANAGER_URL` 使用的内网 IP。

Agent 申请始终以中心看到的 TCP 来源 IP 为准，不读取代理转发头。若待确认项显示反向代理地址，说明 `MANAGER_URL` 配错；把它改为中心内网直连 IP，而不是浏览器使用的代理域名。

### Agent 未出现在待确认列表

待确认申请只依赖 Agent 主动访问中心 `33801`；中心访问 Agent `33802` 是点击“确认”时的下一阶段。因此关闭防火墙并不能替代对进程、监听地址、路由、版本和时间的逐层检查，也不应通过 flush 规则排障。

先在 Agent 主机检查进程、本地健康、非敏感连接配置和本次启动日志：

```bash
sudo systemctl status iptables-web-agent --no-pager
curl -i http://127.0.0.1:33802/api/v1/health
sudo grep -E '^(MANAGER_URL|AGENT_PUBLIC_URL|AGENT_LISTEN_ADDR)=' /etc/iptables-web-agent/agent.env
sudo journalctl -u iptables-web-agent -b --no-pager | grep -E 'enrollment|registration|rejected|failed|authentication|listening'
timedatectl status
```

不要收集或发送完整 EnvironmentFile、`agent.identity` 或 `agent.key.sha256`。日志状态的含义：

- `pending`：中心已经接收申请，继续检查管理员页面和待确认列表 API；
- `approved`：该身份已纳管，应到“纳管概览”查找，而不是待确认列表；
- `rejected`：管理员拒绝后该身份隐藏 24 小时；
- `connection refused`：中心未在目标地址监听，或端口填错；
- `i/o timeout`：检查路由、ACL、安全组和实际目标地址；
- `clock differs ... more than 5m`：同步 Agent 与中心时间；
- `invalid controller response`、HTTP 404 或 HTML：通常访问了旧版中心、错误端口或普通反向代理。

再从 Agent 主机直连中心内网 IP。空申请预期得到 HTTP 400 与 `invalid_enrollment`，这证明当前中心存在正确的公开注册路由：

```bash
curl -i --connect-timeout 5 http://中心内网IP:33801/api/v1/health
curl -i --connect-timeout 5 -X POST -H 'Content-Type: application/json' -d '{}' \
  http://中心内网IP:33801/api/v1/agent-enrollments/register
```

最后在中心检查监听和是否收到注册请求；容器部署把 `journalctl` 换成对应容器日志：

```bash
sudo ss -lntp | grep ':33801'
sudo systemctl status iptables-web --no-pager
sudo journalctl -u iptables-web -b --no-pager | grep 'agent-enrollments/register'
```

中心应监听 `0.0.0.0:33801` 或实际内网 IP，而不是只监听 `127.0.0.1:33801`。两端时间差必须小于 5 分钟，待确认列表仅管理员可见。

## 安装后无法远端访问

按顺序确认：

1. `LISTEN_ADDR` 是 `0.0.0.0:端口`，且 ss 显示 `*:端口`。
2. 本机通过实际网卡 IP curl 成功。
3. firewalld 活跃 Zone 绑定了哪张接口。
4. Zone 是否放行该端口/来源，云安全组和上游 ACL 是否允许。
5. 客户端到服务端是否有路由。

安装器不会配置 firewalld 或放行端口，也不添加拒绝规则。应用健康响应正常时，不要通过清空防火墙来“验证”。

## firewalld 与页面不一致

这是当前设计：页面只显示 packet 后端；`firewall-cmd --list-all` 显示独立的 firewalld 配置。宿主机服务由 firewalld 管理，Docker 发布端口由 DOCKER-USER/FORWARD 管理。

## Docker 映射关闭规则后仍不通

检查链上是否仍有其他规则、规则是否由外部工具创建、Docker 是否重新生成链：

```bash
sudo iptables -nvL DOCKER-USER --line-numbers
sudo iptables -nvL FORWARD --line-numbers
sudo iptables-save | grep -E '18080|DOCKER-USER|DROP|REJECT'
docker ps --format '{{.ID}} {{.Names}} {{.Ports}}'
```

再确认 FORWARD 确实进入 DOCKER-USER，并在访问测试时观察哪条规则的计数器增长：

```bash
sudo iptables -t filter -S FORWARD | grep -- '-j DOCKER-USER'
sudo iptables -t filter -nvL DOCKER-USER --line-numbers
```

Docker 页会执行同类只读检查，并显示当前浏览器请求到达服务器时的来源 IP。VMware NAT/Host-only 下，这个地址可能是 VMware 虚拟网卡地址，而不是物理网卡地址。`-p 18080:80` 的正确方向是“宿主机 `:18080` → 容器 `:80`”。

若 ACCEPT 计数始终为 0、兜底 DROP 持续增长，检查 ACCEPT 是否错误地同时出现：

```text
tcp dpt:18080 ctorigdstport 18080
```

对 `18080→80`，DOCKER-USER 中普通 `dpt` 已是容器端口 80，不能再要求它等于宿主机端口 18080。界面规则应只保留 `ctorigdstport 18080`。新版会在启动时精确删除这类旧托管表达式、清空其普通 `dport`，然后重新同步；不会 flush 链。

如果 ACCEPT 与 DROP 计数同时增长，通常表示请求方向被允许、返回方向又被兜底 DROP 拦截。正确规则还必须显示连接方向限制：

```text
ctorigdstport 18080 ctdir ORIGINAL
```

`ORIGINAL` 只匹配客户端到容器的原始方向，容器返回包会继续经过后续的 ESTABLISHED/RELATED 处理。升级时后端会兼容识别并精确删除没有 `ctdir ORIGINAL` 的旧托管表达式，再加入新表达式。

禁用按钮只切换该条托管记录，不代表删除所有匹配端口的外部规则。新版把运行态规则“不存在”视为幂等删除，不会因 `iptables -C ... exit status 1` 阻止关闭。

## 规则排序

选择具体链、清空搜索条件后，至少两条规则时可以直接拖动排序。调整先形成草稿，点击“保存顺序”才同步。程序阻止将宽范围 DROP/REJECT 排到匹配白名单 ACCEPT 前面。

创建或编辑规则时，第一次点击只会显示字段级变更预览；确认后才写入运行防火墙。

## 审计、回滚、备份与恢复

中心本机审计包含用户、主机、Agent 审批和密钥管理信息，因此仅管理员可查看并导出完整 JSON；普通用户仍可查看其授权远程 Agent 自己的防火墙审计。默认文件：

```text
/var/lib/iptables-web/audit.jsonl
```

中心代理远程变更时会在 Agent Key 认证成功后传递已认证的用户名、角色、原始来源 IP 和请求 ID；浏览器 Bearer Token 不会发送给 Agent。新版 Agent 因此会把远程授权操作记录为实际用户名，而不是笼统的 `api-key`。旧版 Agent 或历史记录仍可能显示 `api-key`。页面“查看详情”展示方法、路径、请求 ID，以及规则、用户、主机、访问密钥元数据或安全策略的脱敏前后差异；导出 JSON 保留同样的信息。

每次成功改变托管规则后会保留 10 分钟回滚窗口。系统管理页需要二次确认才会回滚；回滚成功后，原状态成为新的反向回滚点。默认快照：

```text
/var/lib/iptables-web/rollback.json
```

限时回滚只覆盖本程序托管规则，不替代完整 packet 备份，也不能恢复 Docker、firewalld 或其他工具的外部规则。

### 完整备份

系统页“下载全部备份”会生成组合 JSON，其中包含 `packet.rules` 和 `managed-rules.json`。恢复时在系统页选择该 JSON 文件，不需要打开或复制文件内容。命令行也可备份：

```bash
sudo iptables-save > /root/iptables-backup-$(date +%F-%H%M%S).rules
sudo nft list ruleset > /root/nft-backup-$(date +%F-%H%M%S).nft
sudo cp -a /var/lib/iptables-web /root/iptables-web-data-backup
```

中心多主机恢复时，`hosts.json` 与 `hosts.key` 必须来自同一次备份，否则加密凭据无法解密。Agent 应同时备份 `/var/lib/iptables-web-agent` 和 `/etc/iptables-web-agent`；不要只恢复 identity 或只恢复 key hash。

如果中心改用外部 `HOST_CREDENTIAL_KEY`，必须在恢复时提供完全相同的值；安装器升级会自动保留已有 EnvironmentFile 中的值。该变量是中心加密 `hosts.json` 内 Agent 凭据的主密钥，不是需要人工分发给 Agent 的访问密钥。

## 管理员账户解锁

“管理员锁定”模式下，任一仍可登录的管理员可在“用户与权限”页直接解锁账户，原密码不变。系统不会永久锁定最后一个仍可登录的管理员，而会改用配置的定时锁定，以保留恢复入口。若数据来自旧版本且所有管理员已经永久锁定，可使用预先创建的中心 API 访问密钥调用 `POST /api/v1/users/{id}/unlock`；没有可用会话或密钥时，应先备份 `users.json`，再通过受控的离线恢复流程处理，不能删除整个用户文件。

选择与你实际后端匹配的命令。

### 恢复完整规则集

Web 恢复接口会先检查清单和规则语法，备份当前状态，再替换完整 packet 规则集。组合 JSON 会同时恢复托管元数据和可用的 IPv6 导出。任一步骤失败时程序会尝试回滚。

恢复会替换系统规则，执行前仍必须审核备份内容并保留带外控制台。数据文件含义和恢复机制见[架构与实现](architecture.md#审计备份与恢复)。

## 清理与卸载

### 只清理本程序托管规则

```bash
sudo systemctl stop iptables-web
sudo RULES_FILE=/var/lib/iptables-web/rules.json \
  USERS_FILE=/var/lib/iptables-web/users.json \
  FIREWALL_BACKEND=auto \
  /usr/local/bin/iptables-web --cleanup
```

这是首选清理方式：只删除托管规则并清空托管记录，不 flush 外部链。

### 卸载

默认卸载会先精确删除界面托管规则。也可以先在系统管理页点击“清空界面配置的规则”，确认运行态和托管记录均已清空，再卸载：

```bash
sudo /opt/iptables-web/uninstall.sh
```

`--purge` 是兼容保留的完整清理别名，不会修改或 reload firewalld。若托管规则清理失败，脚本默认停止并保留文件和数据，避免失去恢复依据；只有明确接受残留时才使用 `--force`。

## 手动清空全部 packet 规则（高风险）

只有在具备物理/带外控制台、已备份规则、能接受 Docker/网络中断时才执行。远程 SSH 会话中不要执行。

先停止会自动重建规则的服务并备份：

```bash
sudo systemctl stop iptables-web
sudo iptables-save > /root/iptables-before-flush.rules
sudo ip6tables-save > /root/ip6tables-before-flush.rules
sudo nft list ruleset > /root/nft-before-flush.ruleset
```

iptables 后端：先把内置链策略改为 ACCEPT，再清空各表，降低立即断链风险：

```bash
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -t filter -F
sudo iptables -t filter -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t raw -F
sudo iptables -t raw -X
```

IPv6 如需一并清空，使用对应 `ip6tables` 命令，并先把 INPUT/FORWARD/OUTPUT 策略设为 ACCEPT。

如果系统本身还有独立维护的原生 nftables ruleset：

```bash
sudo nft flush ruleset
```

这些操作会移除 Docker 和 firewalld 底层生成的规则，可能导致端口发布、NAT、转发和主机保护同时失效。恢复示例：

```bash
sudo iptables-restore < /root/iptables-before-flush.rules
sudo ip6tables-restore < /root/ip6tables-before-flush.rules
```

firewalld/Docker 重启也可能重新生成规则，但不能把它当成可靠回滚方案。

## 容器运行检查

```bash
docker compose ps
docker compose logs --tail=200 iptables-web
docker inspect iptables-web --format '{{json .State.Health}}'
docker inspect iptables-web --format '{{.HostConfig.NetworkMode}} {{json .HostConfig.CapAdd}}'
docker stats --no-stream iptables-web
```

NetworkMode 应为 `host`，能力应包含 `NET_ADMIN`、`NET_RAW`。默认 Compose 限制为 1 CPU、512 MiB 内存。容器健康但规则没有作用到宿主机时，优先检查是否误用了非 host network；不要用 flush 验证。
