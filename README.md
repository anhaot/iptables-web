# iptables-web

iptables-web 是面向 Linux 主机与 Docker 发布端口的 Web 防火墙管理器。当前版本只通过 `iptables` 命令管理 packet 规则，包括使用 nft 内核实现的 `iptables-nft` 兼容层。原生 nftables 运行后端已禁用，避免规则被错误写入更早的 raw PREROUTING；这不影响规则助手生成和解读 nft 命令。

程序不读取、不编辑、不启停 firewalld Zone 或 rich rule。你可以继续在程序外使用 firewalld 管理未经过 Docker 转发的宿主机服务；Docker 发布端口则在本程序中使用 `FORWARD` / `DOCKER_USER` 管理。

## 当前功能

- 默认监听 `0.0.0.0:33801`，支持从外部访问；认证默认开启。
- 管理 INPUT、FORWARD、OUTPUT、DOCKER、DOCKER_USER 中的托管规则。
- 新增、编辑、启停、删除、拖动排序；白名单顺序检查。
- Docker 发布端口按 IPv4 / IPv6 分类，首页默认只显示 IPv4。
- Docker 映射只接受 Docker socket/CLI 确认的数据，不把普通 `/proc` 监听端口或未发布的 `80/tcp` 猜成宿主机映射。
- Docker 页显示管理页面连接到 33801 时服务器看到的 TCP 对端地址（不宣称是物理机真实 IP，也不保证 Docker 请求路径相同），并检查 `FORWARD → DOCKER-USER` 是否真实可用；链路不可用时禁止创建无效规则。
- IPv4 Docker 映射可快速创建阻止规则或“允许来源 + 兜底 DROP”白名单。
- IPv6 Docker 映射目前在端口页只读；规则助手可生成 `ip6tables` / nftables 命令供审核。
- 规则助手保留“生成命令”和“命令解读”两个入口，支持 iptables、ip6tables、nftables 和 firewalld；firewalld 只生成/解读文本，不进入规则管理。
- 一键完整导出 packet 规则集、托管记录与清单。
- 预编译包安装、源码安装、完全手动安装和干净卸载。

## 安全边界

安装器始终：

- 监听 `0.0.0.0:33801`；
- 启用登录认证；
- 不执行任何 `firewall-cmd` 命令；
- 不新增 DROP / REJECT；
- 新安装且 `rules.json` 为空时，不新增任何 packet 规则。

因此“进程已监听但远端仍打不开”通常表示现有 firewalld、云安全组、上游 ACL 或路由没有放行。请按你的实际 Zone 与来源策略手工处理。不要为了测试清空整套防火墙，也不要添加会影响 SSH/管理链路的拒绝规则。

示例：仅允许管理网段访问 Web 管理端口（请先确认 Zone、来源和回滚通道）：

```bash
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.220.0/24" port port="33801" protocol="tcp" accept' --permanent
sudo firewall-cmd --reload
```

这只是管理员手工配置 firewalld；iptables-web 不会显示或接管它。

## 推荐：安装预编译包

目标机器不需要 Go。先核对压缩包和 SHA-256：

```bash
sha256sum -c iptables-web-<版本>-linux-amd64.tar.gz.sha256
tar -xzf iptables-web-<版本>-linux-amd64.tar.gz
cd iptables-web-<版本>-linux-amd64
sudo bash install-binary.sh
```

安装脚本会校验二进制版本能力、复制文件、创建 systemd 服务，并停止/重启同名旧服务，保证运行的是新二进制。默认地址为：

```text
http://服务器IP:33801
```

首次登录账号为 `admin` / `admin123`，登录后必须立即修改密码。检查安装：

```bash
sudo systemctl status iptables-web --no-pager
sudo systemctl show iptables-web -p ExecStart -p Environment
sudo ss -lntp | grep 33801
curl http://127.0.0.1:33801/api/v1/health
```

常用安装变量：

```bash
# 更换端口，仍允许外部连接；firewalld 由管理员在程序外维护
sudo LISTEN_ADDR=0.0.0.0:33888 bash install-binary.sh

# 强制使用 iptables
sudo FIREWALL_BACKEND=iptables bash install-binary.sh

```

安装器不接受自动放行 firewalld 端口的选项。需要开放管理端口时，由管理员在程序外手工配置。

## 源码安装

```bash
sudo bash scripts/install.sh
```

此脚本可编译源码并完成与预编译安装相同的 systemd 配置。生产环境优先使用预编译包，减少目标机工具链差异。

## 完全手动安装

下面的步骤不依赖安装脚本，也不会执行任何防火墙命令。

```bash
sudo install -d -m 0755 /opt/iptables-web /var/lib/iptables-web
sudo install -m 0755 bin/iptables-web /usr/local/bin/iptables-web
sudo cp README.md /opt/iptables-web/README.md
```

创建 `/etc/systemd/system/iptables-web.service`：

```ini
[Unit]
Description=iptables-web Firewall Manager
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/iptables-web
Environment=RULES_FILE=/var/lib/iptables-web/rules.json
Environment=USERS_FILE=/var/lib/iptables-web/users.json
Environment=LISTEN_ADDR=0.0.0.0:33801
Environment=LOG_LEVEL=info
Environment=AUTH_ENABLED=true
Environment=FIREWALL_BACKEND=auto
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/iptables-web
ReadOnlyPaths=/proc /sys
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

然后：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now iptables-web
```

手动安装后仍需由管理员按现有策略放行管理端口。

## Docker 部署

```bash
docker compose up -d --build
```

容器必须使用 host network，并具有 `NET_ADMIN` / `NET_RAW`，否则只能看到或修改容器自己的网络命名空间。挂载 Docker socket 可获得最准确的端口映射：

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

## Docker 与链的选择

- 宿主机进程监听的端口：`INPUT`。
- Docker 发布端口：`DOCKER_USER`（推荐）或 `FORWARD`。
- `-p 18080:80` 的用户访问端口是 18080；Docker DNAT 后普通 `dport` 可能已变成 80，因此本程序用 `original_dport=18080` 匹配，并自动增加 `--ctdir ORIGINAL`，避免兜底 DROP 拦截容器返回包。
- 使用 `original_dport` 时普通 `dport` 必须留空。错误组合 `--dport 18080 --ctorigdstport 18080` 在 `18080→80` 映射中不会命中 ACCEPT；程序会拒绝新建这种组合，并在升级时精确迁移旧托管规则。
- 白名单必须先 ACCEPT 指定来源，再 DROP/REJECT 其他来源。
- 禁用托管规则时，如果运行态中该规则已被外部删除，程序会把“不存在”视为幂等结果，并按存储记录重新同步链，不再因 `iptables -C ... exit status 1` 阻止切换。

## firewalld 的职责

firewalld 不控制 Docker 转发路径时，可采用以下分工：

- firewalld：在程序外管理 SSH、Cockpit、iptables-web 管理端口等宿主机服务。
- iptables-web：管理 Docker 发布端口以及明确选择的 packet 链。

界面不会再显示 firewalld INPUT、Zone、来源 `*` 或 rich rule，也不会出现只能编辑 public 的问题。`firewall-cmd --list-all` 与规则管理页不需要一致，因为它们现在是两个独立管理面。

## 规则助手

“规则助手”页面保留两个入口：

1. 生成命令：按场景、链、地址族、协议、来源和端口生成 iptables/ip6tables/nftables/firewalld 命令。
2. 命令解读：可粘贴一条或多条 iptables、nft 或 firewall-cmd 命令，显示链/Zone、动作、协议、来源、端口和明显风险。

助手生成的是待审核命令，不会自动执行。DOCKER_USER 场景会使用 DNAT 前原始目标端口；连续多条未指定位置的 `iptables -I` 会提示顺序反转风险。

Docker 的 `-p 18080:80` 表示“访问宿主机 `:18080` → 容器 `:80`”。自动描述按这个方向显示，例如：`允许 192.168.220.1 访问 宿主机:18080 → nginx:80`。在 VMware NAT、代理或 VPN 环境中，虚拟机实际看到的来源地址可能不是物理网卡地址；点击“只允许 IP”时会默认填入服务器从当前浏览器请求中看到的地址。白名单 ACCEPT 与兜底 DROP 由服务端整体保存和同步，失败时整体回滚。

## 备份与恢复

系统管理页不再选择备份范围，点击“下载全部备份”即可一次得到：

- `packet.rules`：完整 iptables-save 或 nft ruleset；
- `managed-rules.json`：程序托管记录；
- `manifest`：后端、状态和说明。

组合 JSON 包含 IPv4、可用时的 IPv6、托管元数据和清单。在系统页点击“选择备份 JSON”即可直接恢复，不需要打开或粘贴文件内容。恢复会先校验并保存回滚副本，但完整规则集操作风险仍然较高，操作前必须保留带外控制台或可靠回滚通道。

## 升级行为

从曾支持 firewalld 管理的版本升级时，程序会：

1. 在 `rules.json.pre-iptables-only.bak` 备份旧应用记录；
2. 从应用存储中移除 `backend=firewalld` 的旧记录；
3. 不调用 firewall-cmd，不删除主机上已有的 firewalld 配置。

## 卸载

发布包内提供 `uninstall.sh`：

```bash
# 默认干净卸载：先精确删除界面托管规则，再删除服务、二进制、文档和数据
sudo bash uninstall.sh

# 兼容保留的完整清理别名；同样不会修改 firewalld
sudo bash uninstall.sh --purge
```

可选项：

```text
--keep-data              保留 users.json 和 rules.json
--remove-rules           删除程序托管规则（默认行为）
--keep-rules             明确保留运行中的托管规则（不推荐）
--force                  清理规则失败时仍继续删文件
```

也可先在“系统管理 → 清空界面托管规则”中执行清理，再卸载。卸载脚本不会调用 `firewall-cmd`、不会 reload firewalld、不会 flush 整条链，也不会猜测哪些外部规则属于本程序。

## 手动清理

只清理本程序托管规则（推荐）：

```bash
sudo systemctl stop iptables-web
sudo RULES_FILE=/var/lib/iptables-web/rules.json \
  USERS_FILE=/var/lib/iptables-web/users.json \
  FIREWALL_BACKEND=auto \
  /usr/local/bin/iptables-web --cleanup
```

不要把“清空所有防火墙规则”当作常规排障手段。确实需要清空整套 packet 规则时，请先准备控制台和备份；参考 [运维手册](docs/operations.md#手动清空全部-packet-规则高风险)。

## 配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LISTEN_ADDR` | `0.0.0.0:33801` | HTTP 监听地址 |
| `RULES_FILE` | `/data/rules.json` | 托管规则存储 |
| `USERS_FILE` | 与规则文件同目录的 `users.json` | 用户与会话存储 |
| `LOG_LEVEL` | `info` | 日志级别 |
| `AUTH_ENABLED` | `true` | 是否要求认证 |
| `API_KEY` | 空 | 脚本调用可选 API Key |
| `FIREWALL_BACKEND` | `auto` | `auto`、`iptables`、`iptables-nft`、`iptables-legacy`、`dev`；`nft`/`nftables` 会明确拒绝启动 |

## 开发与发布

```bash
GOCACHE=/tmp/iptables-web-go-cache go test ./...
node scripts/ui-logic-test.js
VERSION=20260717.11 bash scripts/build-package.sh
bash scripts/verify-package.sh dist/iptables-web-20260717.11-linux-amd64.tar.gz
```

离线校验只检查压缩包、校验和、二进制版本和嵌入前端，不启动服务，也不读取或修改防火墙。

更多资料：

- [部署手册](docs/deployment.md)
- [配置说明](docs/configuration.md)
- [API](docs/api.md)
- [运维与排障](docs/operations.md)
- [架构](docs/architecture.md)
