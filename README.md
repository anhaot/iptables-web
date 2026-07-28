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

## 功能概览

| 能力 | 说明 |
| --- | --- |
| 规则管理 | 新增、编辑、启停、删除和同链排序，保存前预览变化 |
| Docker 访问控制 | 发现真实发布端口，为 IPv4 映射配置允许来源和兜底阻止 |
| 风险控制 | 校验规则范围、白名单顺序和 Docker 端口匹配，写入后核验 |
| 用户认证 | 验证码、角色权限、首次登录强制改密和旧会话撤销 |
| 审计与回滚 | 记录管理员变更，导出审计，并在 10 分钟内回滚最近规则变更 |
| 备份与清理 | 导出完整规则及托管信息，只精确清理程序拥有的规则 |
| 规则助手 | 生成或解释 iptables、ip6tables、nftables、firewalld 命令，不自动执行 |

## 工作原理

浏览器不直接执行系统命令。页面把规则作为 JSON 交给 Go 服务端，服务端依次完成权限检查、参数校验、变更快照、持久化、iptables 写入、运行态核验和审计记录；任一步失败都会尽量恢复变更前状态。

```text
页面预览并确认
      │
      ▼
Go API：认证 → 校验 → 快照 → 保存
      │
      ▼
iptables 执行层：加锁 → 写入 → 核验
      │
      ▼
Linux packet filter
```

`rules.json` 保存程序希望维持的托管规则，Linux 内核中的 iptables 决定当前真正生效的规则。服务启动和规则变更时会同步两者；所有权标记让程序只处理自己的规则，不会 flush 整条链或删除其他工具的配置。

宿主机服务通常经过 `INPUT`，Docker bridge/NAT 发布端口通常经过 `FORWARD → DOCKER-USER`。对于 `-p 10089:8080`，程序通过 conntrack 匹配 DNAT 前的宿主机端口 `10089`，避免误把容器端口 `8080` 当成发布端口。

组件关系、数据文件、认证、审计和故障恢复的完整说明见[架构与实现](docs/architecture.md)；备份恢复及风险操作见[运维手册](docs/operations.md)。

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

Compose 使用 host network，并授予容器 `NET_ADMIN`、`NET_RAW`。如需自动发现 Docker 发布端口，请在 `docker-compose.yml` 中启用已预留的只读 Docker socket 挂载。

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

系统管理页可下载和恢复完整组合备份。文件内容、恢复语义和应急步骤见[运维手册](docs/operations.md#审计回滚备份与恢复)。

### 卸载

```bash
sudo bash uninstall.sh
```

默认卸载会先精确删除程序托管规则，再移除服务、二进制和数据。保留数据、保留运行规则等选项参见[部署手册](docs/deployment.md)。

## 配置

常用默认值是 `LISTEN_ADDR=0.0.0.0:33801`、`AUTH_ENABLED=true` 和 `FIREWALL_BACKEND=auto`。完整环境变量、systemd 配置、后端选择和网络安全要求统一放在[部署与配置](docs/deployment.md#服务配置)。

## 开发

```bash
go test ./...
go test -race ./...
go vet ./...
node scripts/ui-logic-test.js
bash -n scripts/*.sh
```

本地开发、前端同步、发布包和提交要求见[贡献指南](CONTRIBUTING.md)。

## 文档

- [部署与配置](docs/deployment.md)
- [架构与实现](docs/architecture.md)
- [运维与排障](docs/operations.md)
- [API 文档](docs/api.md)
- [更新计划](docs/roadmap.md)
- [贡献指南](CONTRIBUTING.md)

## 许可证

本项目使用 [MIT License](LICENSE)。
