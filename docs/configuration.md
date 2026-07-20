# 配置说明

## 服务环境变量

| 变量 | 默认值 | 可选值/格式 | 说明 |
| --- | --- | --- | --- |
| `LISTEN_ADDR` | `0.0.0.0:33801` | Go `host:port` | 默认接受外部连接；是否能到达仍取决于现有防火墙和网络策略 |
| `RULES_FILE` | `/data/rules.json` | 绝对路径 | 程序托管规则 |
| `USERS_FILE` | 规则文件同目录下 `users.json` | 绝对路径 | 用户数据；会话和验证码仅保存在内存中 |
| `LOG_LEVEL` | `info` | `debug`、`info`、`warn`、`error`、`off` | 全局日志级别 |
| `AUTH_ENABLED` | `true` | `true` / `false` | 生产环境应保持开启 |
| `API_KEY` | 空 | 字符串 | 自动化脚本可选认证方式 |
| `FIREWALL_BACKEND` | `auto` | `auto`、`iptables`、`iptables-nft`、`iptables-legacy`、`dev` | 选择 packet 后端；`nft`/`nftables` 已禁用并会拒绝启动 |
| `DEV_MODE` | `false` | 精确值 `true` | 使用不执行系统命令的开发后端 |

程序不识别 `FIREWALLD_MANAGED`、`FIREWALLD_PERMANENT`，也不会注册 firewalld 后端。

## 安装脚本变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SKIP_DEP_INSTALL` | `false` | 源码安装时跳过包管理器 |
| `LOCAL_GO_TARBALL` | 空 | 源码安装时指定本地 Go 压缩包 |

安装脚本没有 firewalld 配置变量，也不会执行 `firewall-cmd`。管理端口是否放行由系统管理员在程序外处理。

## 后端选择

`auto` 只探测 `iptables` 命令；该命令可以是 legacy 实现，也可以是 `iptables-nft` 兼容层。程序不再回退到原生 nftables，因为旧实现会把普通规则同时写入 raw PREROUTING，扩大规则作用范围。只有 `nft`、没有 `iptables` 的机器会拒绝启动规则管理，并提示安装 iptables。规则助手仍可生成和解读 nftables 命令文本。

```bash
sudo systemctl edit iptables-web
```

```ini
[Service]
Environment=FIREWALL_BACKEND=iptables
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart iptables-web
```

## 数据兼容

升级时遇到旧 `backend=firewalld` 记录，程序先生成 `rules.json.pre-iptables-only.bak`，再只保留 packet 记录。这个迁移不会调用 firewall-cmd。
