# iptables-web

一个面向 Linux 主机和 Docker 发布端口的轻量级 Web 防火墙管理工具。

iptables-web 提供直观的规则管理、Docker 端口访问控制、变更预览、审计、备份和回滚能力。程序通过 `iptables` 或 `iptables-nft` 兼容层管理自己创建的 packet 规则，不接管 firewalld，也不启用原生 nftables 写入后端。

[功能截图](#功能截图) · [快速安装](#安装部署) · [使用文档](docs/index.md) · [更新计划](docs/roadmap.md) · [问题反馈](https://github.com/anhaot/iptables-web/issues)

> [!IMPORTANT]
> 首次启动会创建 `admin/admin123`。首次登录必须修改密码，完成前服务端会拒绝规则、用户、备份等其他管理请求。当前程序直接提供 HTTP，请仅在可信管理网络中使用，生产环境建议通过 HTTPS 反向代理访问。

## 项目介绍

在 Linux 主机上管理 Docker 防火墙，难点往往不在于写出一条命令，而在于确认它是否写到了正确的链、匹配了 DNAT 前后的正确端口，并且不会因为顺序错误中断现有连接。

iptables-web 主要处理以下场景：

- 管理宿主机 `INPUT`、`OUTPUT` 和转发相关 packet 规则；
- 查看 Docker 确认发布的 IPv4/IPv6 端口映射；
- 为 Docker IPv4 发布端口设置允许来源和兜底阻止策略；
- 保存前预览字段变化，降低规则范围和顺序误判；
- 记录管理员操作，导出审计日志并限时回滚最近变更；
- 备份完整规则集和应用托管信息；
- 生成或解释 iptables、ip6tables、nftables、firewalld 命令。

程序只管理自己的规则。firewalld Zone、rich rule 和其他工具创建的规则仍由原管理工具维护。

## 功能特性

### 防火墙规则

- 新增、编辑、启停和删除托管规则；
- 在具体链中拖动调整执行顺序；
- 支持 `INPUT`、`FORWARD`、`OUTPUT`、`DOCKER`、`DOCKER_USER`；
- 校验宽范围 DROP/REJECT、白名单顺序和冲突端口条件；
- 保存前显示字段级变更预览；
- 写入后核验运行态规则，失败时恢复原状态。

### Docker 访问控制

- 通过 Docker socket 或 Docker CLI 获取真实发布映射；
- IPv4、IPv6 映射分类展示；
- 按容器、端口和来源地址搜索；
- 显示允许来源、兜底规则、实际位置和残留策略；
- 检查 `FORWARD → DOCKER-USER` 是否为有效流量路径；
- 一次保存“允许来源 + 兜底 DROP/REJECT”完整白名单策略。

### 安全与运维

- 登录验证码、角色权限和服务端会话校验；
- 默认管理员首次登录强制改密；
- 管理员新建用户或重置密码后，用户下次登录必须改密；
- 密码修改、用户删除或密码重置后撤销旧会话；
- 保存管理员、来源地址、请求结果及规则/用户前后差异；
- 完整导出审计日志；
- 最近一次规则变更提供 10 分钟双确认回滚；
- 一键备份 IPv4、可用的 IPv6 规则集和托管元数据；
- 精确清理托管规则，不 flush 系统链，不修改 firewalld。

## 实现原理

iptables-web 由一个 Go 服务端和原生 HTML/CSS/JavaScript 前端组成，前端资源通过 Go `embed` 编入单个二进制。

```text
浏览器
  │  登录 / 预览 / 确认
  ▼
Go HTTP API
  ├─ 会话与角色校验
  ├─ 参数和规则顺序校验
  ├─ 变更审计与回滚快照
  └─ JSON 原子持久化
        │
        ▼
iptables 执行层
  ├─ xtables 锁等待
  ├─ 命令超时
  ├─ 所有权 comment
  └─ 写入后核验
        │
        ▼
Linux packet filter
```

Docker 发布端口经过 DNAT 后，普通目标端口可能已经变成容器端口。程序使用 conntrack 的 `--ctorigdst`、`--ctorigdstport` 和 `--ctdir ORIGINAL` 匹配访问者最初请求的宿主机地址和端口。

规则、用户、审计和回滚数据分别保存在独立文件中。所有管理写请求串行执行；审计中间件比较操作前后的快照并记录差异，成功的规则变更同时保存限时回滚快照。

更多技术细节参见[架构说明](docs/architecture.md)和[安全说明](docs/security.md)。

## 功能截图

### 仪表盘

![iptables-web 仪表盘](docs/images/dashboard.png)

### Docker 端口与访问策略

![Docker 发布端口与访问策略](docs/images/docker-policy.png)

### 管理员审计与限时回滚

![管理员变更审计与限时回滚](docs/images/change-audit.png)

截图来自 `DEV_MODE=true` 的本地演示环境，不会修改主机防火墙。

## 安装部署

### 环境要求

- Linux；
- root 权限，或等效的 `NET_ADMIN`、`NET_RAW` 能力；
- iptables、iptables-nft 或 iptables-legacy；
- 管理 Docker 发布端口时，需要 Docker socket 或 Docker CLI。

### 使用发布包

从 [GitHub Releases](https://github.com/anhaot/iptables-web/releases) 下载压缩包及对应的 SHA-256 文件：

```bash
sha256sum -c iptables-web-<版本>-linux-amd64.tar.gz.sha256
tar -xzf iptables-web-<版本>-linux-amd64.tar.gz
cd iptables-web-<版本>-linux-amd64
sudo bash install-binary.sh
```

安装完成后访问：

```text
http://服务器IP:33801
```

首次登录：

```text
用户名：admin
密码：admin123
```

登录后页面会要求立即设置新密码。在完成改密前，其他管理接口不可用。

### 从源码安装

需要 Go 1.26.5：

```bash
git clone https://github.com/anhaot/iptables-web.git
cd iptables-web
sudo bash scripts/install.sh
```

### Docker Compose

```bash
git clone https://github.com/anhaot/iptables-web.git
cd iptables-web
docker compose up -d --build
```

Compose 使用 host network，并授予容器 `NET_ADMIN`、`NET_RAW`。默认只读挂载 Docker socket，用于读取准确的端口映射。

### 检查服务

```bash
sudo systemctl status iptables-web --no-pager
sudo ss -lntp | grep 33801
curl http://127.0.0.1:33801/api/v1/health
```

安装器不会自动调整 firewalld、云安全组或上游 ACL。需要远程访问时，请由管理员按照现有网络策略限制可信来源。

## 使用说明

### 如何选择链

| 流量类型 | 推荐链 |
| --- | --- |
| SSH、Web、数据库等宿主机监听端口 | `INPUT` |
| Docker bridge/NAT 发布端口 | `DOCKER_USER` |
| 明确需要处理的转发流量 | `FORWARD` |
| 宿主机主动发出的流量 | `OUTPUT` |

Docker 白名单应先允许指定来源，再阻止其他来源。不要在没有带外控制台的情况下创建宽范围 DROP 或 REJECT。

### Docker 端口匹配

Docker 的 `-p 18080:80` 表示：

```text
访问宿主机 :18080 → 转发到容器 :80
```

Docker 转发策略应填写“原始宿主机端口”`18080`，普通 `dport` 留空。程序会生成 DNAT 前目标端口匹配条件，避免把宿主机端口和容器端口混用。

### firewalld 分工

- firewalld：继续管理 SSH、Cockpit、iptables-web 管理端口等宿主机服务；
- iptables-web：管理 Docker 发布端口和明确选择的 packet 链。

iptables-web 不会执行 `firewall-cmd`，不会 reload firewalld，也不会删除 firewalld 配置。

### 备份与恢复

系统管理页可下载完整组合备份，内容包括 packet 规则集、可用的 IPv6 导出、托管规则和版本清单。恢复完整规则集属于高风险操作，执行前应保留带外控制台。

### 卸载

```bash
sudo bash uninstall.sh
```

默认卸载会先精确删除程序托管规则，再移除服务、二进制和数据。保留数据、保留运行规则等选项参见[部署手册](docs/deployment.md)。

## 配置

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LISTEN_ADDR` | `0.0.0.0:33801` | HTTP 监听地址 |
| `RULES_FILE` | `/data/rules.json` | 托管规则存储 |
| `USERS_FILE` | 与规则文件同目录的 `users.json` | 用户和会话数据 |
| `AUDIT_FILE` | 与规则文件同目录的 `audit.jsonl` | 管理员变更审计 |
| `ROLLBACK_FILE` | 与规则文件同目录的 `rollback.json` | 最近规则变更快照 |
| `LOG_LEVEL` | `info` | 日志级别 |
| `AUTH_ENABLED` | `true` | 是否启用登录认证 |
| `API_KEY` | 空 | 自动化调用使用的可选 API Key |
| `FIREWALL_BACKEND` | `auto` | `auto`、`iptables`、`iptables-nft`、`iptables-legacy`、`dev` |

显式配置 `nft` 或 `nftables` 时，服务会拒绝启动。原生 nftables 仍可通过规则助手生成和解释命令，但不会被 Web 管理功能直接执行。

## 开发

```bash
go test ./...
go test -race ./...
go vet ./...
node scripts/ui-logic-test.js
bash -n scripts/*.sh
```

构建发布包：

```bash
VERSION=<版本号> bash scripts/build-package.sh
bash scripts/verify-package.sh dist/iptables-web-<版本号>-linux-amd64.tar.gz
```

发布压缩包上传到 GitHub Releases，不提交到源码分支。贡献代码前请阅读[贡献指南](CONTRIBUTING.md)。

## 文档

- [部署手册](docs/deployment.md)
- [配置说明](docs/configuration.md)
- [API 文档](docs/api.md)
- [运维与排障](docs/operations.md)
- [架构说明](docs/architecture.md)
- [开发指南](docs/development.md)
- [安全说明](docs/security.md)
- [更新计划](docs/roadmap.md)

## 许可证

本项目使用 [MIT License](LICENSE)。
