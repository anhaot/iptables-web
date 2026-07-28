# 运维与排障

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

## 管理员审计与最近变更回滚

系统管理页显示最近管理员变更，并可导出完整 JSON 审计。默认文件：

```text
/var/lib/iptables-web/audit.jsonl
```

每次成功改变托管规则后会保留 10 分钟回滚窗口。系统管理页需要二次确认才会回滚；回滚成功后，原状态成为新的反向回滚点。默认快照：

```text
/var/lib/iptables-web/rollback.json
```

限时回滚只覆盖本程序托管规则，不替代完整 packet 备份，也不能恢复 Docker、firewalld 或其他工具的外部规则。

## 备份

系统页“下载全部备份”会生成组合 JSON，其中包含 `packet.rules` 和 `managed-rules.json`。恢复时在系统页选择该 JSON 文件，不需要打开或复制文件内容。命令行也可备份：

```bash
sudo iptables-save > /root/iptables-backup-$(date +%F-%H%M%S).rules
sudo nft list ruleset > /root/nft-backup-$(date +%F-%H%M%S).nft
sudo cp -a /var/lib/iptables-web /root/iptables-web-data-backup
```

选择与你实际后端匹配的命令。

## 只清理本程序托管规则

```bash
sudo systemctl stop iptables-web
sudo RULES_FILE=/var/lib/iptables-web/rules.json \
  USERS_FILE=/var/lib/iptables-web/users.json \
  FIREWALL_BACKEND=auto \
  /usr/local/bin/iptables-web --cleanup
```

这是首选清理方式：只删除托管规则并清空托管记录，不 flush 外部链。

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

## 恢复完整规则集

Web 恢复接口会先做语法校验和当前状态备份，再替换完整 packet 规则集；组合 JSON 会同时恢复托管元数据和可用的 IPv6 规则。任一步骤失败时程序会尝试回滚。执行前仍必须审核内容并准备带外回滚。

## 卸载

默认卸载会先精确删除界面托管规则。也可以先在系统管理页点击“清空界面配置的规则”，确认运行态和托管记录均已清空，再卸载：

```bash
sudo /opt/iptables-web/uninstall.sh
```

`--purge` 是兼容保留的完整清理别名，不会修改或 reload firewalld。若托管规则清理失败，脚本默认停止并保留文件/数据，避免失去恢复依据；只有明确接受残留时才用 `--force`。
