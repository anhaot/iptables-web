# 部署与配置

本文给出可直接执行的中心端和 Agent 部署流程，覆盖发布包脚本、源码、完全手动 systemd、升级、回滚和卸载。日常检查、备份恢复和故障定位见[运维手册](operations.md)，多主机安全边界见[Agent 纳管与按主机授权](multi-host.md)。

## 1. 选择部署方式

| 场景 | 中心端 | Agent | 建议 |
| --- | --- | --- | --- |
| 普通生产主机 | 发布包 `install-binary.sh` | 发布包 `install-agent.sh` | 首选；不需要 Go，自动校验 systemd、启动和健康状态 |
| 内网源码环境 | `scripts/install.sh` | 仍使用发布包 Agent | 源码安装会低并发编译，再走同一事务安装流程 |
| 受控变更平台 | 手动 systemd | 手动 systemd | 使用仓库 `deploy/systemd/` 模板，便于配置管理系统审计 |

安装脚本只管理程序文件、私有配置目录和自己的 systemd unit。它们不会执行 `firewall-cmd`、不会开放端口、不会 flush 链，也不会删除其他工具的规则。

### 1.1 推荐的内网拓扑

下面的地址贯穿本文示例，请替换成实际管理网 IP：

```text
管理员浏览器 ───────────────► 中心端 10.0.0.5:33801
                                  ▲
                                  │ Agent 主动签名申请/心跳
                                  │
目标机 10.0.0.21:33802 ◄─────────┘ 中心按来源 IP 回连
目标机 10.0.0.22:33802 ◄─────────┘
```

中心端同时是控制平面和一台可管理的本机防火墙；目标机只运行无界面 Agent。内网部署以 IP 为准：每台 Agent 的 `MANAGER_URL` 直接填写中心内网 IP，`AGENT_PUBLIC_URL` 填写该目标机能被中心访问的内网 IP。DNS 不是必需条件。

## 2. 部署前检查

支持 Linux amd64 发布包，systemd 脚本适用于 Ubuntu 20.04+、Debian 11+、RHEL/CentOS/Rocky/AlmaLinux 7+ 和麒麟 V10 等常见发行版。安装及运行时使用 root 权限，以便管理宿主机防火墙。

先安装最小运行依赖。发行版的软件包名称可能随版本变化，以下是常见命令：

```bash
# Debian / Ubuntu
sudo apt-get update
sudo apt-get install -y iptables ca-certificates curl

# RHEL / Rocky / AlmaLinux / CentOS Stream
sudo dnf install -y iptables-services ca-certificates curl
```

发布包脚本还需要 `tar`、`sha256sum`、`systemctl` 和 `systemd-analyze`。源码部署另外需要 Git 和 Go。路径校验需要 GNU coreutils 中的 `realpath`。`jq` 只用于可选的端到端烟测，不是服务运行依赖。

```bash
uname -m
cat /etc/os-release
systemctl --version | head -n 1
iptables --version
command -v curl
timedatectl status
```

要求：

- `uname -m` 与发布包架构一致；
- 存在 iptables、iptables-nft 或 iptables-legacy；原生 nftables 写入不受支持；
- 中心默认监听 TCP `33801`，Agent 默认监听 TCP `33802`；
- Agent 与中心时间误差不超过 5 分钟；
- 中心必须能回连 Agent 声明的协议和端口；
- 远程部署前保留现有 SSH 会话，涉及宽范围拒绝规则时准备带外控制台。

从中心验证目标机回连端口，从目标机验证中心申请端口：

```bash
# 在中心端执行
curl --connect-timeout 3 http://10.0.0.21:33802/api/v1/health

# 在目标机执行
curl --connect-timeout 3 http://10.0.0.5:33801/api/v1/health
```

健康接口无需密钥，只用于存活检查；其他 Agent API 会要求每台主机独立的密钥。安装前若端口已被占用，应先用 `ss -lntp` 查明进程，不要直接终止未知服务。

## 3. 发布包脚本部署中心端（推荐）

### 3.1 校验并解压

同时下载压缩包和同名 `.sha256` 文件：

```bash
sha256sum -c iptables-web-<版本>-linux-amd64.tar.gz.sha256
tar -xzf iptables-web-<版本>-linux-amd64.tar.gz
cd iptables-web-<版本>-linux-amd64
./bin/iptables-web --version
./bin/iptables-web-agent --version
```

校验文件缺失或哈希不一致时不要安装。

### 3.2 安装

```bash
sudo bash install-binary.sh
```

常用自定义示例：

```bash
sudo LISTEN_ADDR=127.0.0.1:33801 \
  FIREWALL_BACKEND=auto \
  LOG_LEVEL=info \
  bash install-binary.sh
```

安装器的常用环境变量：

| 变量 | 默认 | 用途 |
| --- | --- | --- |
| `LISTEN_ADDR` | `0.0.0.0:33801` | 服务监听地址 |
| `FIREWALL_BACKEND` | `auto` | `auto`、`iptables`、`iptables-nft`、`iptables-legacy` 或仅测试用的 `dev` |
| `AUTH_ENABLED` | `true` | 是否启用登录；生产必须为 `true` |
| `LOG_LEVEL` | `info` | 日志级别 |
| `DATA_DIR` | `/var/lib/iptables-web` | 持久化数据目录 |
| `CONFIG_DIR` | `/etc/iptables-web` | 私有 EnvironmentFile 目录 |
| `INSTALL_DIR` | `/opt/iptables-web` | 文档、卸载器和安装元数据目录 |
| `HOST_CREDENTIAL_KEY` | 空 | 可选外部主密钥；通常不要设置，已设置后不得更换 |
| `SKIP_FIREWALL_DEP_INSTALL` | `false` | 依赖已离线准备时跳过包管理器 |
| `DRY_RUN` | `false` | 只渲染并校验 unit，不写系统 |

变更默认目录时应使用绝对路径，并让 `DATA_DIR`、EnvironmentFile、systemd 的 `ReadWritePaths` 和备份方案保持一致。脚本会拒绝根目录、过宽的系统目录、系统运行目录及带控制字符的路径。路径必须是规范绝对路径，不得包含 `..`、重复或尾部斜杠，也不能经过符号链接；DATA_DIR/CONFIG_DIR/INSTALL_DIR 必须是程序专用目录，不能指向 `/usr/local/bin` 等共享目录。BIN_DIR 可使用 `/usr/local/bin`。卸载同样检查路径，避免通过别名误删上层目录。

脚本会：

1. 校验参数、iptables 依赖和二进制 `--version`；
2. 渲染并用 `systemd-analyze verify` 检查 unit；
3. 备份本次升级前的二进制、unit 和 EnvironmentFile；
4. 原子替换二进制，执行 `daemon-reload`、`enable` 和 `restart`；
5. 最多等待 15 秒检查本机健康接口；
6. systemd 或健康检查失败时恢复旧文件和原有启用/运行状态。

安装器绝不会在 systemd 失败后退回成无人管理的后台进程。失败时以非零状态退出，并打印最近日志。

默认文件：

| 路径 | 权限 | 内容 |
| --- | --- | --- |
| `/usr/local/bin/iptables-web` | `0755` | 中心二进制 |
| `/etc/iptables-web/iptables-web.env` | `0600` | 运行配置；仅显式使用外部主密钥时含 `HOST_CREDENTIAL_KEY` |
| `/etc/systemd/system/iptables-web.service` | `0644` | systemd unit |
| `/var/lib/iptables-web` | `0700` | 规则、用户、主机、审计和加密材料 |
| `/opt/iptables-web` | `0755` | 文档、元数据和卸载脚本 |

为了避免中心 API 访问密钥明文落盘，安装器拒绝非空 `API_KEY`。安装完成后可在“用户与权限”页面创建、撤销动态访问密钥；列表和磁盘只保存不可逆摘要，明文只在创建成功时显示一次。这些密钥仅供外部 API 集成，不是 Agent Key；Agent Key 由进程自动交换。

绝大多数部署不需要设置 `HOST_CREDENTIAL_KEY`：中心会生成 `/var/lib/iptables-web/hosts.key`，它与 `hosts.json` 必须成对备份。若已有部署显式使用外部 `HOST_CREDENTIAL_KEY`，升级脚本会从原 `0600` EnvironmentFile 原样保留；也可在运行安装器时再次传入同一个至少 32 字符的值，不能随意更换。

### 3.3 安装后验证

```bash
sudo systemctl is-enabled iptables-web
sudo systemctl is-active iptables-web
sudo systemctl status iptables-web --no-pager -l
sudo systemctl cat iptables-web
sudo stat -c '%a %U:%G %n' /etc/iptables-web/iptables-web.env /var/lib/iptables-web
curl --fail --show-error http://127.0.0.1:33801/api/v1/health
sudo ss -lntp | grep ':33801'
```

首次账号是 `admin/admin123`，登录后必须立即改密。在首次改密完成前，服务端拒绝其他管理操作。

如目标机安装了 `curl`、`jq` 和 Go，可在源码目录运行不接触真实防火墙的完整烟测：

```bash
make integration-test
```

该脚本强制使用开发后端和回环监听，验证主动申请、批准、受保护回连、Agent 无页面边界、远程规则增删、审计以及密钥落盘检查，不会执行系统防火墙命令。它属于源码仓库的开发验证工具，不进入面向目标机的 Release 压缩包；正式包由发布工作流在上传前执行同等构建与离线校验。

## 4. 从源码部署中心端

本地构建发布压缩包还需要 Python 3，用于公开文件边界和文档检查；发布包目标机器不需要 Python 或 Go。

源码要求 Go 1.26+，仓库声明的工具链为 Go 1.26.5：

```bash
git clone https://github.com/anhaot/iptables-web.git
cd iptables-web
git status --short
sudo BUILD_PROCS=2 bash scripts/install.sh
```

`BUILD_PROCS` 默认是 2，同时限制 `GOMAXPROCS` 和 Go 构建并发。源码脚本只负责编译，系统安装仍委托给与发布包相同的事务安装器。可用变量：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `BUILD_PROCS` | `2` | Go 构建并发，资源较小的机器可设为 `1` |
| `SKIP_DEP_INSTALL` | `false` | 已离线准备依赖时跳过包管理器 |
| `LOCAL_GO_TARBALL` | 空 | 指定本地 `go*.linux-amd64.tar.gz` |
| `GO_VERSION_MIN` | `1.26` | 最低 Go 主次版本 |

本地 Go 压缩包会安装到独立的 `/usr/local/go-iptables-web-<版本>`，不会删除已有 `/usr/local/go`。

## 5. 完全手动 systemd 部署中心端

以下流程适合 Ansible、Salt、Puppet 或严格变更窗口。先从已校验发布包目录执行：

```bash
sudo install -d -m 0755 /opt/iptables-web /etc/systemd/system
sudo install -d -m 0700 /etc/iptables-web /var/lib/iptables-web
sudo install -m 0755 bin/iptables-web /usr/local/bin/iptables-web
sudo install -m 0644 deploy/systemd/iptables-web.service /etc/systemd/system/iptables-web.service
sudo install -m 0600 deploy/systemd/iptables-web.env.example /etc/iptables-web/iptables-web.env
sudo install -m 0644 README.md /opt/iptables-web/README.md
```

编辑 `/etc/iptables-web/iptables-web.env`：

```ini
RULES_FILE="/var/lib/iptables-web/rules.json"
USERS_FILE="/var/lib/iptables-web/users.json"
HOSTS_FILE="/var/lib/iptables-web/hosts.json"
API_KEYS_FILE="/var/lib/iptables-web/api-keys.json"
AUDIT_FILE="/var/lib/iptables-web/audit.jsonl"
ROLLBACK_FILE="/var/lib/iptables-web/rollback.json"
LISTEN_ADDR="0.0.0.0:33801"
LOG_LEVEL="info"
AUTH_ENABLED="true"
FIREWALL_BACKEND="auto"
```

不要在该文件中加入 `API_KEY`。多主机凭据加密主密钥默认由中心首次启动时生成到数据目录的 `hosts.key`，必须与 `hosts.json` 一起备份。

校验并启动：

```bash
sudo systemd-analyze verify /etc/systemd/system/iptables-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now iptables-web
curl --fail http://127.0.0.1:33801/api/v1/health
```

unit 不依赖 `docker.service`，因此未安装或未启动 Docker 不会阻塞中心启动。Docker 端口发现是可选能力。

## 6. 使用 systemd 部署 Agent（推荐）

### 6.1 脚本安装

把同一发布包复制到每台目标机，进入解压目录：

```bash
sudo MANAGER_URL=http://10.0.0.5:33801 \
  AGENT_NAME=prod-node-01 \
  AGENT_GROUP=production \
  AGENT_PUBLIC_URL=http://10.0.0.21:33802 \
  bash install-agent.sh --non-interactive
```

在终端直接执行 `sudo bash install-agent.sh` 会进入交互模式。非终端环境必须设置 `MANAGER_URL`，不会无限等待输入。

常用 Agent 安装变量：

| 变量 | 默认 | 用途 |
| --- | --- | --- |
| `MANAGER_URL` | 必填 | 中心直连 HTTP(S) 地址，无路径、查询参数或账号信息 |
| `AGENT_PUBLIC_URL` | 自动探测 | 中心可回连的本机地址；生产建议显式填写内网 IP |
| `AGENT_LISTEN_ADDR` | `0.0.0.0:33802` | Agent API 监听地址 |
| `AGENT_NAME` | 短主机名 | 中心初始显示名称 |
| `AGENT_GROUP` | 空 | 初始主机组 |
| `MANAGER_CA_FILE` | 空 | Agent 校验 HTTPS 中心所用的私有 CA 源文件 |
| `FIREWALL_BACKEND` | `auto` | 目标机防火墙兼容后端 |
| `ROTATE_AGENT_KEY` | `false` | 明确轮换凭据；普通升级不要设置 |
| `DRY_RUN` | `false` | 只验证安装事务，不改系统 |

HTTPS 中心使用私有 CA 时，把 CA 源文件传给安装器；安装器会复制到固定的 `/etc/iptables-web-agent/manager-ca.pem`，后续升级自动保留：

```bash
sudo MANAGER_URL=https://10.0.0.5 \
  MANAGER_CA_FILE=/root/downloads/manager-ca.pem \
  AGENT_PUBLIC_URL=http://10.0.0.21:33802 \
  bash install-agent.sh --non-interactive
```

Agent 安装器同样执行二进制校验、unit 校验、原子替换、systemd 重启、15 秒健康检查和失败回滚。`ROTATE_AGENT_KEY=true` 只在明确要求时轮换；若新版本启动失败，旧哈希也会恢复。普通升级和重启不会清理运行中的托管规则。

验证：

```bash
sudo systemctl is-enabled iptables-web-agent
sudo systemctl is-active iptables-web-agent
sudo systemctl status iptables-web-agent --no-pager -l
sudo journalctl -u iptables-web-agent -n 50 --no-pager
curl --fail http://127.0.0.1:33802/api/v1/health
sudo ss -lntp | grep ':33802'
sudo stat -c '%a %U:%G %n' /etc/iptables-web-agent/agent.env \
  /etc/iptables-web-agent/agent.identity /etc/iptables-web-agent/agent.key.sha256
```

Agent 启动后每 15 秒向中心提交签名申请/心跳。在中心“Agent 纳管”页确认；只有中心用独立凭据成功回连状态接口后才加入主机清单。

### 6.2 完全手动安装 Agent

```bash
sudo install -d -m 0755 /etc/systemd/system
sudo install -d -m 0700 /etc/iptables-web-agent /var/lib/iptables-web-agent
sudo install -m 0755 bin/iptables-web-agent /usr/local/bin/iptables-web-agent
sudo install -m 0644 deploy/systemd/iptables-web-agent.service \
  /etc/systemd/system/iptables-web-agent.service
sudo install -m 0600 deploy/systemd/iptables-web-agent.env.example \
  /etc/iptables-web-agent/agent.env
sudo editor /etc/iptables-web-agent/agent.env
sudo systemd-analyze verify /etc/systemd/system/iptables-web-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now iptables-web-agent
curl --fail http://127.0.0.1:33802/api/v1/health
```

`/etc/iptables-web-agent/agent.env` 至少应包含：

```ini
AGENT_LISTEN_ADDR="0.0.0.0:33802"
AGENT_KEY_HASH_FILE="/etc/iptables-web-agent/agent.key.sha256"
AGENT_IDENTITY_FILE="/etc/iptables-web-agent/agent.identity"
RULES_FILE="/var/lib/iptables-web-agent/rules.json"
FIREWALL_BACKEND="auto"
MANAGER_URL="http://10.0.0.5:33801"
MANAGER_CA_FILE=""
AGENT_PUBLIC_URL="http://10.0.0.21:33802"
AGENT_NAME="prod-node-01"
AGENT_GROUP="production"
LOG_LEVEL="info"
```

必须按实际网络修改 `MANAGER_URL`、`AGENT_PUBLIC_URL`、名称和分组。若中心使用私有 CA，先执行 `sudo install -m 0600 manager-ca.pem /etc/iptables-web-agent/manager-ca.pem`，再把 `MANAGER_CA_FILE` 指向该绝对路径。不要手工创建 Agent Key：进程首次启动自动交换凭据，目标机磁盘只保存 SHA-256，中心加密保存凭据。

## 7. 服务配置

### 7.1 中心端环境变量

| 变量 | 默认/推荐 | 说明 |
| --- | --- | --- |
| `LISTEN_ADDR` | `0.0.0.0:33801` | HTTP 监听 `host:port` |
| `RULES_FILE` | 规则目录下 `rules.json` | 中心本机托管规则 |
| `monitoring-policy.json` | 与 `RULES_FILE` 同目录，无独立环境变量 | 在线检测全局设置（0600）；在“用户与权限”中修改，主机可独立覆盖，详见[多主机手册](multi-host.md#在线检测设置) |
| `USERS_FILE` | 同目录 `users.json` | 用户数据；安全策略保存在同目录 `security-policy.json` |
| `HOSTS_FILE` | 同目录 `hosts.json` | 远程主机清单和加密凭据 |
| `API_KEYS_FILE` | 同目录 `api-keys.json` | 动态访问密钥 ID、名称和单向摘要 |
| `AUDIT_FILE` | 同目录 `audit.jsonl` | 追加式受认证变更审计 |
| `ROLLBACK_FILE` | 同目录 `rollback.json` | 最近规则变更快照 |
| `LOG_LEVEL` | `info` | `debug`、`info`、`warn`、`error`、`off` |
| `AUTH_ENABLED` | `true` | 生产必须保持认证；`false` 会让页面拥有管理员能力 |
| `FIREWALL_BACKEND` | `auto` | `auto`、`iptables`、`iptables-nft`、`iptables-legacy`、`dev` |
| `HOST_CREDENTIAL_KEY` | 自动 `hosts.key` | 可选外部主密钥；设置后至少 32 字符且永远保持稳定 |
| `DEV_MODE` | `false` | 仅开发使用；`true` 不执行系统防火墙命令 |

新增/编辑主机、批准 Agent、创建/撤销动态访问密钥都由数据存储实时生效，不需要重启中心。只有修改监听地址、日志级别、后端等进程环境变量才需要重启。

### 7.2 Agent 环境变量

| 变量 | 默认/示例 | 说明 |
| --- | --- | --- |
| `AGENT_LISTEN_ADDR` | `0.0.0.0:33802` | Agent 固定 API 监听 |
| `MANAGER_URL` | 必填 | 无路径、查询参数或用户信息的中心 HTTP(S) 地址；主动注册推荐直连中心内网 IP |
| `MANAGER_CA_FILE` | 空 | 中心私有 CA 的源文件；安装器复制到 Agent 配置目录 |
| `AGENT_PUBLIC_URL` | 自动探测 | 中心可回连的协议和端口；中心固定请求来源 IP |
| `AGENT_NAME` | 主机名 | 1–64 位字母、数字、点、下划线、连字符 |
| `AGENT_GROUP` | 空 | 0–64 位受限显示分组 |
| `FIREWALL_BACKEND` | `auto` | 与中心相同的 iptables 后端选择 |

Agent 没有用户、认证会话、中心主机清单、访问密钥管理或任意 URL 代理，不能把这些能力加入远程代理。

显式选择 `FIREWALL_BACKEND=iptables-legacy` 时需要 `iptables-legacy`、`iptables-legacy-save`、`iptables-legacy-restore`；选择 `iptables-nft` 时需要对应的 nft 兼容命令。IPv6 备份/恢复使用同家族的 `ip6tables-legacy-*` 或 `ip6tables-nft-*`。`auto` 与 `iptables` 使用系统默认 alternatives；显式家族缺失时启动失败，不回退到默认后端。

## 8. 网络和 HTTPS

中心与 Agent 的 Go 进程当前直接提供 HTTP。HTTP 只适合可信隔离网络；公网或跨不可信网络必须使用 VPN、零信任隧道，或在中心和每台 Agent 前分别提供 HTTPS 反向代理。HTTP/HTTPS 是每台远程主机的独立属性，不是全局开关；新增主机、修改某台主机的 CA、创建或撤销动态访问密钥都不需要重启中心。

建议 ACL：

- 中心 `33801`：只允许管理员网段和各 Agent 主动申请来源；
- Agent `33802`：只允许中心端 IP；
- SSH：保持现有管理来源，不要通过清空规则排障；
- 云环境同时检查安全组、网络 ACL、路由和主机防火墙。

### 8.1 内网直连 IP（推荐基线）

多主机纳管依赖 Agent 到中心的真实 TCP 来源 IP。服务端不信任 `Forwarded` 或 `X-Forwarded-For`，因此 Agent 的 `MANAGER_URL` 必须直接指向中心内网 IP，而不是普通七层反向代理：

```ini
# 中心端；也可使用 0.0.0.0:33801 后由 ACL 限制
LISTEN_ADDR="10.0.0.5:33801"

# 目标机 Agent
MANAGER_URL="http://10.0.0.5:33801"
AGENT_PUBLIC_URL="http://10.0.0.21:33802"
```

若中心只绑定具体内网 IP，本文其他命令中的 `http://127.0.0.1:33801` 应相应替换为 `http://10.0.0.5:33801`；回环地址不会自动命中只绑定在内网网卡上的监听。

中心收到申请后会把 Agent 地址固定为请求来源 IP，只保留 Agent 声明的协议和端口。即使 Agent 提交了其他主机名或 IP，也不会让中心回连任意地址。目标机 ACL 应只允许 `10.0.0.5` 访问 `33802`。

只有单机使用、没有远程 Agent 主动申请时，中心才适合仅监听回环并完全放在反向代理后：

```ini
LISTEN_ADDR="127.0.0.1:33801"
```

多主机场景仍可给浏览器增加 HTTPS 入口，但中心的内网直连监听必须保留给 Agent，并由网络 ACL 保护。不要把明文 HTTP 管理端口暴露到公网。

### 8.2 浏览器访问中心的 Nginx HTTPS 示例

下面示例假设 Nginx 与中心在同一台机器，证书已由企业 CA 或公开 CA 签发。多主机场景的 `proxy_pass` 可改为 `http://10.0.0.5:33801`：

```nginx
server {
    listen 443 ssl http2;
    server_name firewall.example.internal;

    ssl_certificate     /etc/nginx/tls/controller.crt;
    ssl_certificate_key /etc/nginx/tls/controller.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 17m;
    location / {
        proxy_pass http://127.0.0.1:33801;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 125s;
    }
}
```

校验并重载：

```bash
sudo nginx -t
sudo systemctl reload nginx
curl --fail https://firewall.example.internal/api/v1/health
```

反向代理只保护浏览器入口，不改变 Agent 注册时的来源 IP 规则。不要把 Agent 的 `MANAGER_URL` 填成上述域名，除非它实际直达中心进程且不会改写 TCP 来源。

### 8.3 为单台 Agent 配置 HTTPS

Agent 的 HTTPS 是逐台配置的。常见做法是让 Agent 进程只监听回环，由同机 Nginx 在该主机内网 IP 上提供 TLS：

```ini
AGENT_LISTEN_ADDR="127.0.0.1:33802"
AGENT_PUBLIC_URL="https://10.0.0.21:3443"
```

```nginx
server {
    listen 10.0.0.21:3443 ssl;
    server_name 10.0.0.21;

    ssl_certificate     /etc/nginx/tls/agent.crt;
    ssl_certificate_key /etc/nginx/tls/agent.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        allow 10.0.0.5;
        deny all;
        proxy_pass http://127.0.0.1:33802;
        proxy_http_version 1.1;
        proxy_read_timeout 125s;
    }
}
```

中心按申请来源 IP `10.0.0.21` 回连，所以证书必须包含 `IP:10.0.0.21` 的 Subject Alternative Name，仅含 DNS 名称或 Common Name 不够。使用私有 CA 时，可按以下方式生成测试/内网证书；生产环境请遵循组织的 PKI 流程并妥善保护 CA 私钥：

```bash
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
  -keyout internal-ca.key -out internal-ca.crt -subj '/CN=iptables-web Internal CA'

openssl req -newkey rsa:3072 -nodes \
  -keyout agent.key -out agent.csr -subj '/CN=10.0.0.21'

printf 'subjectAltName=IP:10.0.0.21\nextendedKeyUsage=serverAuth\n' > agent-ext.cnf
openssl x509 -req -in agent.csr -CA internal-ca.crt -CAkey internal-ca.key \
  -CAcreateserial -out agent.crt -days 825 -sha256 -extfile agent-ext.cnf

openssl x509 -in agent.crt -noout -subject -issuer -ext subjectAltName
curl --cacert internal-ca.crt https://10.0.0.21:3443/api/v1/health
```

Agent 提交申请后，在中心“Agent 纳管”的对应行粘贴 `internal-ca.crt` 的 PEM 内容再批准。CA 只保存到该主机记录；其他 HTTP Agent 或不同 CA 的 HTTPS Agent 不受影响。

### 8.4 中心自身使用私有 CA

如果 Agent 直连的中心地址本身是 HTTPS，中心证书同样必须包含中心 IP SAN。把签发 CA 复制到目标机并在安装时指定：

```bash
sudo MANAGER_URL=https://10.0.0.5:3443 \
  MANAGER_CA_FILE=/root/downloads/controller-ca.crt \
  AGENT_PUBLIC_URL=http://10.0.0.21:33802 \
  bash install-agent.sh --non-interactive
```

安装器会将 CA 复制为 `/etc/iptables-web-agent/manager-ca.pem`，权限设为 `0600`，升级失败时一并回滚。禁止使用跳过证书校验的配置；程序也不提供 `InsecureSkipVerify` 开关。

## 9. 可选的 Docker 发布端口发现

中心和 Agent 均直接安装为宿主机 systemd 服务。只有被管理主机确实运行 Docker、需要识别其发布端口时，才需要该主机具有可访问的 Docker Unix socket 或 Docker CLI；普通防火墙管理不依赖 Docker。

程序先通过 `/var/run/docker.sock` 读取 Docker 的容器端口信息，再尝试 `docker` CLI；两者均不可用时返回空映射列表，不会把普通宿主机监听端口猜成容器发布端口。服务仍可管理 INPUT、OUTPUT 等托管规则。

```bash
# 在实际运行 Docker 的被管理主机上检查
sudo test -S /var/run/docker.sock
sudo docker ps --format 'table {{.Names}}\t{{.Ports}}'
```

Docker socket 本身具有很高的宿主机权限，应保留其原有访问控制，不要改成全员可写，也不要为本程序开放未认证的 Docker TCP API。Docker 发布端口访问控制、DNAT 前后端口区别和 DOCKER-USER 链路排障见[运维手册](operations.md)。

## 10. 升级与回滚

当前同步、清空、回滚和卸载只删除带 `iptables-web:<rule-id>` 所有权注释的规则，启动时也不会自动删除无注释的同条件规则。如果从早期无所有权标记的版本升级，先备份并人工核对残留规则，再安排维护窗口处理；不要通过 flush 系统链来迁移。

### 10.1 脚本升级

中心：

```bash
sudo cp -a /var/lib/iptables-web /root/iptables-web-data-$(date +%F-%H%M%S)
sudo bash install-binary.sh
```

脚本会保留现有 EnvironmentFile 中的外部 `HOST_CREDENTIAL_KEY`。若未配置该变量，则继续使用数据目录里的 `hosts.key`，无需额外传参。

Agent：

```bash
sudo cp -a /var/lib/iptables-web-agent /etc/iptables-web-agent \
  /root/iptables-web-agent-backup-$(date +%F-%H%M%S)
sudo MANAGER_URL=http://中心地址:33801 bash install-agent.sh --non-interactive
```

脚本只在当前安装事务失败时自动恢复二进制/unit/env；它不替代长期数据备份。升级 Agent 不要设置 `ROTATE_AGENT_KEY=true`，除非确实需要轮换。

### 10.2 手动二进制升级

中心示例：

```bash
sudo cp -a /usr/local/bin/iptables-web /usr/local/bin/iptables-web.previous
sudo install -m 0755 bin/iptables-web /usr/local/bin/iptables-web.new
/usr/local/bin/iptables-web.new --version
sudo mv /usr/local/bin/iptables-web.new /usr/local/bin/iptables-web
sudo systemctl restart iptables-web
curl --fail http://127.0.0.1:33801/api/v1/health || {
  sudo mv /usr/local/bin/iptables-web.previous /usr/local/bin/iptables-web
  sudo systemctl restart iptables-web
}
```

Agent 同理替换 `iptables-web-agent`，并检查 `33802` 健康接口。不要在升级前删除身份或 key hash。

## 11. 卸载

中心默认精确删除程序托管规则后再删除服务、二进制、配置和数据：

```bash
sudo /opt/iptables-web/uninstall.sh
```

Agent 在发布包目录或已保存脚本处执行：

```bash
sudo bash uninstall-agent.sh
```

常用选项：

```bash
--keep-rules   # 有意保留当前运行规则
--keep-data    # 保留数据；Agent 同时保留身份和 key hash
--purge --yes  # 无交互完整清理
--force        # 规则精确清理失败后仍删除文件，可能留下规则
```

卸载器不会 flush 链。精确清理失败时默认停止删除并保留恢复依据；修复后重试。注意此时服务已经停止/禁用，需要恢复业务时先执行 `systemctl enable --now <服务名>`。

## 12. 部署验收清单

- `systemctl is-enabled` 和 `is-active` 都成功；
- 健康接口返回 HTTP 200，监听地址与规划一致；
- EnvironmentFile 与数据目录权限正确；
- 中心首次密码已修改，认证未关闭；
- 端口只对规划来源开放，Agent `33802` 只允许中心；
- Agent 时间同步正常，中心能回连并完成审批；
- 新增主机和动态访问密钥无需重启即可生效；
- `hosts.json` 与 `hosts.key` 一起备份，Agent identity/hash 一起备份；
- 日志、审计、列表 API 和磁盘中没有访问密钥明文；

建议把以下输出保存到变更记录中，但不要收集 EnvironmentFile、`hosts.key`、Agent identity 或任何一次性明文密钥：

以下命令按所在主机选择中心或 Agent 项执行；如果服务只绑定具体内网 IP，请把健康检查中的 `127.0.0.1` 换成该 IP。

```bash
iptables-web --version
iptables-web-agent --version
systemctl is-enabled iptables-web iptables-web-agent
systemctl is-active iptables-web iptables-web-agent
curl --fail http://127.0.0.1:33801/api/v1/health
curl --fail http://127.0.0.1:33802/api/v1/health
ss -lntp | grep -E ':33801|:33802'
```

## 13. 部署阶段常见问题

| 现象 | 优先检查 | 处理 |
| --- | --- | --- |
| 安装器提示找不到 iptables | `command -v iptables`、发行版包管理器日志 | 安装 iptables 兼容层；不要把 `FIREWALL_BACKEND` 设为原生 `nftables` |
| systemd unit 校验失败 | `systemd-analyze verify <unit>` | 检查自定义路径、EnvironmentFile 权限和控制字符；修正后重新运行安装器 |
| 服务 active 但健康检查失败 | `journalctl -u iptables-web -n 100`、`ss -lntp` | 检查端口冲突、监听地址、数据文件权限和后端初始化错误 |
| Agent 没出现在待确认列表 | 两端健康接口、`MANAGER_URL`、时间同步、Agent 日志 | 保证 Agent 直连中心内网 IP，时差小于 5 分钟，并允许目标机访问中心端口 |
| 批准 Agent 时回连失败 | `AGENT_PUBLIC_URL`、目标机 ACL、中心到 Agent 的 `curl` | 只允许中心 IP 访问 Agent；HTTPS 时检查证书 IP SAN 和对应 CA |
| Agent 正常上报但显示“回连异常” | 中心到目标机的路由/ACL、Agent 受保护状态接口 | 这表示心跳方向正常、反向连接异常，不要通过重复安装替代网络诊断 |
| 重启后中心无法解密主机凭据 | `hosts.json` 与 `hosts.key` 是否来自同一备份 | 恢复成对文件；外部 `HOST_CREDENTIAL_KEY` 部署必须恢复原值 |
| 页面能打开但无法执行管理操作 | 是否仍使用初始密码、会话角色、本机/主机授权 | 先完成首次改密，再检查管理员或普通用户的 `local`/远程主机授权 |

运行期故障、Docker 链路诊断、账户解锁、备份恢复和高风险清理见[运维与排障](operations.md)。

## 14. 如何判断“真实可用”

仓库把验证分成三层，不能用页面能打开代替防火墙生效检查：

1. `go test ./...`、`go test -race ./...` 和 `go vet ./...` 检查模型、API、存储、认证、注册协议、命令参数、回滚及并发安全；
2. `scripts/integration-smoke.sh` 用真实中心/Agent 进程走完整控制链，但强制使用 no-op 开发后端，不接触宿主机规则；
3. 生产验收必须在目标发行版和实际 iptables 兼容后端上，使用一条低风险、来源明确的 ACCEPT 规则验证“页面记录、`iptables-save` 运行态、业务连通、审计和删除”一致。

Docker、firewalld、云安全组、内核模块、发行版默认策略和上游路由都属于运行环境，仓库测试无法替代现场验收。正式上线前至少选一台与生产同版本的预发布主机，保留 SSH 与带外控制台，完成第 12 节清单和一次备份恢复演练；未完成这一步，不应宣称该环境已经生产可用。
