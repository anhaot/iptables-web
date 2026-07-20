# 架构

```text
Browser
  └─ Web UI / API
       ├─ 用户与会话存储 users.json
       ├─ 托管规则存储 rules.json
       ├─ packet executor
       │    ├─ iptables（优先，含 iptables-nft）
       │    └─ native nftables（回退/强制）
       ├─ Docker 映射发现
       │    ├─ Docker socket
       │    └─ docker CLI（socket 不可用时回退）
       └─ 规则助手（只生成/解读文本）
```

## 规则模型

托管规则包含 backend、chain、action、协议、来源/目标、端口、Docker 原始目标端口、接口、连接状态、位置和启用状态。backend 目前只能是 `packet`。

运行态规则可能被外部工具修改，因此新增、编辑、启停、删除和排序都以同一链的托管记录为声明状态重新同步。删除不存在的 iptables 规则被视为成功，保证启停操作幂等。

程序不会 flush 整条系统链；同步时只尝试删除与托管记录完全匹配的规则，再按有效位置重新加入启用规则。

## Docker 路径

外部请求命中 Docker 发布端口后通常经过 DNAT 和 FORWARD/DOCKER-USER，而不是宿主机 INPUT。`original_dport` 使用 conntrack 的原始目标端口，避免把多个映射到相同容器端口的服务混在一起。

托管模型不允许同时设置 `dport` 与 `original_dport`。前者在 DOCKER-USER 中表示 DNAT 后容器端口，后者表示 DNAT 前宿主机发布端口；把宿主机端口同时写入两者会使端口不同的映射永远无法命中。启动迁移只删除完全匹配的旧托管规则，再以 `original_dport` 重新同步。

iptables 表达式在 `--ctorigdstport` 后增加 `--ctdir ORIGINAL`；nft 表达式使用 `ct direction original`。如果方向不受限，原始连接元组也可能让兜底 DROP 命中容器返回包，表现为 ACCEPT 和 DROP 计数同时增长、客户端最终超时。

Docker 映射只来自 Docker socket 或 Docker CLI。普通 `/proc` 监听端口无法证明来自 Docker，因此不作为映射来源。应用会只读检查 iptables 的 DOCKER-USER 链和 FORWARD 跳转；缺少任一项时不允许通过 Docker 页面创建规则。原生 nftables 后端没有 Docker iptables 的 DOCKER-USER 入口，并且已从运行后端中禁用。

Docker 映射带 `family=ipv4|ipv6`。UI 分开显示，仪表盘只显示 IPv4。IPv6 端口页暂时只读；规则助手可生成 ip6tables/nftables 命令。

## firewalld 边界

firewalld 是外部管理面。程序没有 Zone API、Zone 页面、rich rule 模型或 firewall-cmd 执行器；安装和卸载脚本也不会执行 `firewall-cmd`。规则助手仅生成和解读命令文本，不会执行它们。
