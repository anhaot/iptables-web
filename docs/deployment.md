# 部署与配置

本文集中说明安装方式、服务配置和部署安全边界。运行检查、备份恢复和故障处理见[运维手册](operations.md)。

## 环境要求

- Linux；使用安装脚本时需要 systemd；
- root 权限，或等效的 `NET_ADMIN`、`NET_RAW` 能力；
- iptables、iptables-nft 或 iptables-legacy；
- 管理 Docker 发布端口时，需要只读 Docker socket 或 Docker CLI。

程序不支持原生 nftables 写入后端，也不会配置 firewalld。

## 使用发布包

从 [GitHub Releases](https://github.com/anhaot/iptables-web/releases) 下载压缩包和对应的 SHA-256 文件：

```bash
sha256sum -c iptables-web-<版本>-linux-amd64.tar.gz.sha256
tar -xzf iptables-web-<版本>-linux-amd64.tar.gz
cd iptables-web-<版本>-linux-amd64
sudo bash install-binary.sh
```

安装脚本不要求 Go。它会检查二进制、`--version`、iptables 依赖、目标目录和 systemd，然后安装或重启同名服务。

默认配置：

```text
LISTEN_ADDR=0.0.0.0:33801
AUTH_ENABLED=true
FIREWALL_BACKEND=auto
```

首次账号为 `admin/admin123`。登录后必须先修改密码；完成前，服务端只允许会话检查、改密和退出。

自定义监听地址或后端：

```bash
sudo LISTEN_ADDR=0.0.0.0:33888 \
  FIREWALL_BACKEND=iptables \
  bash install-binary.sh
```

安装器不会开放管理端口，也不会修改现有 packet 规则或 firewalld。

## 从源码安装

```bash
git clone https://github.com/anhaot/iptables-web.git
cd iptables-web
sudo bash scripts/install.sh
```

源码安装需要 Go 1.26.5。脚本会优先使用现有工具链，也可以通过以下变量调整：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SKIP_DEP_INSTALL` | `false` | 跳过包管理器依赖安装 |
| `LOCAL_GO_TARBALL` | 空 | 指定本地 Go 压缩包 |

生产目标机通常更适合使用经过校验的发布包。

## Docker Compose

```bash
git clone https://github.com/anhaot/iptables-web.git
cd iptables-web
docker compose up -d --build
```

Compose 使用 host network，并授予容器 `NET_ADMIN`、`NET_RAW`。这些权限允许容器影响宿主机网络，因此只应使用受信任镜像，并保护数据卷和宿主机访问权限。

如需自动发现 Docker 发布端口，请取消 `docker-compose.yml` 中已预留挂载的注释：

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

只读挂载不等同于低权限；能访问 Docker socket 的进程仍应视为高权限组件。

## 完全手动安装

```bash
sudo install -d -m 0755 /opt/iptables-web
sudo install -d -m 0700 /var/lib/iptables-web
sudo install -m 0755 bin/iptables-web /usr/local/bin/iptables-web
sudo install -m 0755 scripts/uninstall.sh /opt/iptables-web/uninstall.sh
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
Environment=AUDIT_FILE=/var/lib/iptables-web/audit.jsonl
Environment=ROLLBACK_FILE=/var/lib/iptables-web/rollback.json
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

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now iptables-web
```

## 服务配置

| 变量 | 默认值 | 可选值或格式 | 说明 |
| --- | --- | --- | --- |
| `LISTEN_ADDR` | `0.0.0.0:33801` | Go `host:port` | HTTP 监听地址 |
| `RULES_FILE` | `/data/rules.json` | 绝对路径 | 托管规则文件 |
| `USERS_FILE` | 规则目录下 `users.json` | 绝对路径 | 用户数据；会话和验证码只在内存中 |
| `AUDIT_FILE` | 规则目录下 `audit.jsonl` | 绝对路径 | 追加式管理员审计 |
| `ROLLBACK_FILE` | 规则目录下 `rollback.json` | 绝对路径 | 最近规则变更快照 |
| `LOG_LEVEL` | `info` | `debug`、`info`、`warn`、`error`、`off` | 日志级别 |
| `AUTH_ENABLED` | `true` | `true`、`false` | 是否启用登录认证 |
| `API_KEY` | 空 | 字符串 | 自动化脚本的可选认证方式 |
| `FIREWALL_BACKEND` | `auto` | `auto`、`iptables`、`iptables-nft`、`iptables-legacy`、`dev` | packet 后端 |
| `DEV_MODE` | `false` | 精确值 `true` | 使用不执行系统命令的开发后端 |

生产环境应保持 `AUTH_ENABLED=true`。API Key 不应写入公开脚本、日志或仓库。

修改 systemd 环境变量：

```bash
sudo systemctl edit iptables-web
```

```ini
[Service]
Environment=FIREWALL_BACKEND=iptables
Environment=LISTEN_ADDR=127.0.0.1:33801
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart iptables-web
```

`auto` 探测系统中的 `iptables` 命令，该命令可以是 legacy 实现，也可以是 iptables-nft 兼容层。显式配置 `nft` 或 `nftables` 时服务会拒绝启动；规则助手仍可生成和解释 nftables 文本。

升级旧数据时，如果发现 `backend=firewalld` 记录，程序会先生成 `rules.json.pre-iptables-only.bak`，再只保留 packet 记录。迁移不会调用 `firewall-cmd`。

## 网络与安全

默认监听 `0.0.0.0:33801`，但安装器不会放行端口。管理员应通过 firewalld、云安全组、VPN、反向代理或上游 ACL 限制可信来源。

服务没有内建 TLS。跨不可信网络访问时，应将 `LISTEN_ADDR` 改为回环地址，并通过 HTTPS 反向代理暴露：

```text
浏览器 ──HTTPS──► 反向代理 ──HTTP/127.0.0.1──► iptables-web
```

不要将明文 HTTP 管理端口直接暴露到公网。

程序的管理边界：

- 只管理 IPv4 packet 托管规则；
- 不读取或修改 firewalld Zone；
- 不执行 `firewall-cmd` 或 reload firewalld；
- 不在新安装时创建拒绝规则；
- 不 flush 未知链或删除外部规则。

数据目录应为 `0700`，`users.json`、`rules.json`、`audit.jsonl` 和 `rollback.json` 应为 `0600`。默认安装器会设置这些权限。

## 检查服务

```bash
sudo systemctl status iptables-web --no-pager
sudo systemctl show iptables-web -p ExecStart -p Environment
sudo ss -lntp | grep 33801
curl http://127.0.0.1:33801/api/v1/health
```

本机健康检查成功但远端无法访问时，继续按[运维手册](operations.md#安装后无法远端访问)检查 firewalld、云安全组和路由，不要通过清空防火墙验证。

## 升级

升级前备份 `/var/lib/iptables-web`，并在系统管理页下载完整备份。然后在新发布包目录执行：

```bash
sudo bash install-binary.sh
```

安装器会替换二进制并重启现有服务，不会修改 firewalld。

## 卸载

```bash
# 默认精确删除托管规则，再卸载服务和文件
sudo bash uninstall.sh

# 兼容保留的完整清理别名
sudo bash uninstall.sh --purge
```

默认模式和 `--purge` 都不会 flush 链、删除未知外部规则或修改 firewalld。若必须保留当前运行规则，可使用 `--keep-rules`。清理失败时脚本默认保留程序与数据；只有明确接受残留时才使用 `--force`。
