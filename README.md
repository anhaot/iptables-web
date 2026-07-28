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

### 先用一句话理解

iptables-web 并不是让浏览器直接执行 `iptables` 命令，而是把你在网页中填写的规则变成一份结构化请求，交给 Go 服务端完成校验、写入、核验、审计和失败恢复。

例如，你在页面中创建“只允许 `10.10.0.0/16` 访问 Docker 发布端口 `10089`”，完整过程是：

1. 页面收集链、来源地址、端口和动作，先显示变更预览，此时不会修改防火墙。
2. 点击确认后，浏览器把规则作为 JSON 发送给 Go API。
3. 服务端检查登录状态、首次改密状态和管理员权限。
4. 服务端校验 IP、端口、链、动作和规则顺序，拒绝无法命中或可能误伤流量的组合。
5. 服务端保存变更前快照，并将本次写操作与其他写操作串行执行。
6. 规则先写入 `rules.json`，再转换为实际的 iptables 参数。
7. 命令执行后，服务端重新读取运行状态进行核验；执行或保存失败会恢复变更前状态。
8. 最后记录操作者、来源地址、修改内容和执行结果，并开启 10 分钟回滚窗口。

### 程序由哪些部分组成

项目由一个 Go 服务端和原生 HTML、CSS、JavaScript 前端组成。前端资源通过 Go `embed` 编入二进制，因此部署时只需要一个服务程序和数据目录，不需要单独安装 Node.js、数据库或 Web 服务器。

```text
浏览器
  │  登录、填写规则、预览并确认
  ▼
Go HTTP API
  ├─ 验证会话、首次改密状态和角色权限
  ├─ 校验 IP、端口、链、动作和执行顺序
  ├─ 保存变更前快照
  ├─ 原子更新 JSON 数据
  └─ 记录审计事件
        │
        ▼
iptables 执行层
  ├─ 等待 xtables 系统锁，避免与其他工具同时写入
  ├─ 为命令设置超时
  ├─ 使用 comment 标记程序拥有的规则
  ├─ 按链和位置写入规则
  └─ 写入后重新读取并核验
        │
        ▼
Linux 内核中的 packet filter
```

### 网页中的规则和系统规则是什么关系

程序同时维护两种状态：

- `rules.json` 是“希望系统保持的规则”，用于页面展示、重启恢复和判断规则归属；
- Linux 内核中的 iptables 是“当前真正生效的规则”，决定网络数据包是否放行。

新增、编辑、启停、删除和排序时，服务端会根据 `rules.json` 重新同步对应链，并检查运行状态。服务启动后也会重新同步已启用规则，所以宿主机或容器重启后不需要手工重新添加。

程序为自己写入的规则增加所有权标记。删除、同步和卸载时只处理这些托管规则，不会 `flush` 整条链，也不会删除 Docker、firewalld 或其他工具创建的规则。

### 为什么宿主机端口和 Docker 端口处理方式不同

宿主机服务和 Docker 发布端口经过的网络路径不同：

```text
访问宿主机 SSH / 管理页面
客户端 ──► 宿主机端口 ──► INPUT ──► 宿主机进程

访问 Docker 发布端口
客户端 ──► 宿主机:10089 ──► DNAT ──► 容器:8080
                              │
                              └──► FORWARD ──► DOCKER-USER
```

因此：

- SSH、宿主机 Web 服务和数据库通常在 `INPUT` 链管理；
- Docker bridge/NAT 发布端口通常在 `DOCKER_USER` 链管理；
- `-p 10089:8080` 经过 DNAT 后，普通 `dport` 看到的可能已经是容器端口 `8080`，而不是用户访问的宿主机端口 `10089`。

为避免匹配错端口，程序使用 conntrack 的 `--ctorigdst`、`--ctorigdstport` 和 `--ctdir ORIGINAL`，按连接最初访问的宿主机 IP 和端口匹配。Docker 白名单会让指定来源的 `ACCEPT` 位于兜底 `DROP` 或 `REJECT` 之前，并在保存前检查顺序。

### 数据如何保存和恢复

默认数据目录中包含：

| 文件 | 保存内容 | 用途 |
| --- | --- | --- |
| `rules.json` | 页面托管的规则 | 展示、同步和重启恢复 |
| `users.json` | 用户、密码哈希、角色和强制改密状态 | 身份认证和权限控制 |
| `audit.jsonl` | 每次管理员变更的追加记录 | 查询责任人和修改内容 |
| `rollback.json` | 最近一次规则变更前的快照 | 10 分钟内快速恢复 |

JSON 数据使用临时文件写入并原子替换，避免进程中断时留下半个文件。完整备份还会包含 `iptables-save` 导出的 IPv4、可用时的 IPv6 规则集和托管规则清单。

### 登录和首次改密如何保证不能绕过

登录成功后，服务端创建会话，浏览器把 Token 保存在当前标签页的 `sessionStorage` 中，后续 API 请求通过 Bearer Token 携带会话身份。

默认管理员、新建用户和被管理员重置密码的用户会带有“必须修改密码”状态。这个限制不只存在于页面跳转中：认证中间件会在服务端拒绝其他管理 API，只允许会话检查、修改本人密码和退出。改密成功后，服务端清除该状态并撤销用户的全部旧会话。

当前服务直接提供 HTTP，传输加密需要由 HTTPS 反向代理提供。不要把 HTTP 管理端口直接暴露到不可信网络。

### 审计和回滚如何工作

规则或用户发生变更时，审计中间件会比较操作前后的快照，记录操作者、来源地址、请求 ID、HTTP 结果和字段变化，但不会记录密码或会话 Token。

每次成功修改托管规则后，程序保存修改前快照并开启 10 分钟回滚窗口。回滚时会先保存当前状态，再恢复旧规则并重新核验，因此成功回滚后仍可以反向恢复。审计和回滚针对本程序管理的内容，不等同于操作系统级审计。

### 规则助手为什么不会直接执行命令

规则助手用于生成或解释 iptables、ip6tables、nftables 和 firewalld 文本，帮助管理员理解命令。生成结果只展示和复制，不会自动执行；Web 规则管理仍只写入 iptables 或 iptables-nft 兼容后端。

更底层的模型和执行约束参见[架构说明](docs/architecture.md)，部署边界参见[安全说明](docs/security.md)。

## 功能截图

点击图片可以查看原始尺寸。

<table>
  <tr>
    <td width="50%" align="center">
      <a href="docs/images/login.png"><img src="docs/images/login.png" alt="登录页面"></a><br>
      <sub>登录：账号密码、验证码和登录状态提示</sub>
    </td>
    <td width="50%" align="center">
      <a href="docs/images/first-login-password.png"><img src="docs/images/first-login-password.png" alt="首次登录强制修改密码"></a><br>
      <sub>首次改密：完成前服务端不会开放其他管理接口</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <a href="docs/images/dashboard.png"><img src="docs/images/dashboard.png" alt="iptables-web 仪表盘"></a><br>
      <sub>仪表盘：系统、规则和 Docker 端口概览</sub>
    </td>
    <td width="50%" align="center">
      <a href="docs/images/rules.png"><img src="docs/images/rules.png" alt="防火墙规则管理"></a><br>
      <sub>规则管理：搜索、分链查看、启停、编辑和排序</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <a href="docs/images/rule-editor.png"><img src="docs/images/rule-editor.png" alt="规则编辑与变更预览"></a><br>
      <sub>规则编辑：填写匹配条件并在写入前核对字段变化</sub>
    </td>
    <td width="50%" align="center">
      <a href="docs/images/chains.png"><img src="docs/images/chains.png" alt="实时链浏览器"></a><br>
      <sub>链浏览器：只读查看系统当前的 packet 链和规则</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <a href="docs/images/docker-policy.png"><img src="docs/images/docker-policy.png" alt="Docker 发布端口访问策略"></a><br>
      <sub>Docker 端口：查看发布映射、允许来源和兜底规则</sub>
    </td>
    <td width="50%" align="center">
      <a href="docs/images/rule-assistant.png"><img src="docs/images/rule-assistant.png" alt="防火墙规则助手"></a><br>
      <sub>规则助手：按场景生成命令或解释已有命令</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <a href="docs/images/system-management.png"><img src="docs/images/system-management.png" alt="系统管理、备份、审计和回滚"></a><br>
      <sub>系统管理：用户、备份、恢复、审计和限时回滚</sub>
    </td>
    <td width="50%" valign="middle">
      <strong>截图说明</strong><br><br>
      截图来自 <code>DEV_MODE=true</code> 的本地演示环境。开发后端不会修改主机防火墙；页面流程、API 校验、数据持久化和审计逻辑与正常模式一致。
    </td>
  </tr>
</table>


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
VERSION=0.1.0 bash scripts/build-package.sh
bash scripts/verify-package.sh dist/iptables-web-0.1.0-linux-amd64.tar.gz
```

正式版本使用 `v主版本.次版本.修订版本` 格式，例如 `v0.1.0`。版本 Tag 推送后，GitHub Actions 会运行测试、构建 Linux amd64 压缩包和 SHA-256 校验文件，并创建对应的 GitHub Release。发布产物不会提交到源码分支。

贡献代码前请阅读[贡献指南](CONTRIBUTING.md)。

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
