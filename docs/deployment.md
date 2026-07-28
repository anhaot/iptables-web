# 部署手册

## 1. 预编译包（推荐）

```bash
sha256sum -c iptables-web-<版本>-linux-amd64.tar.gz.sha256
tar -xzf iptables-web-<版本>-linux-amd64.tar.gz
cd iptables-web-<版本>-linux-amd64
sudo bash install-binary.sh
```

安装脚本不要求 Go，会检查：压缩包校验和（从 dist 自动提取时）、二进制可执行性、`--version` 支持、iptables 依赖、目标目录和 systemd。iptables-nft 兼容层受支持，原生 nftables 后端不受支持。

同名旧服务正在运行时，脚本会复制新二进制后重启它；不会让旧进程继续占用端口。

默认配置：

```text
LISTEN_ADDR=0.0.0.0:33801
AUTH_ENABLED=true
FIREWALL_BACKEND=auto
```

安装器不会执行任何 `firewall-cmd`，也不会修改 firewalld。默认不修改 iptables 或 nftables；新安装的规则文件为空，服务启动不会新增 packet 规则。

## 2. 自定义预编译安装

```bash
sudo LISTEN_ADDR=0.0.0.0:33888 \
  FIREWALL_BACKEND=iptables \
  bash install-binary.sh
```

firewalld 由管理员在程序外维护。安装器没有自动放行 Zone/端口的选项。

## 3. 源码安装

```bash
sudo bash scripts/install.sh
```

脚本会优先使用可用 Go 工具链，也可使用本地 Go 压缩包或已有 dist 预编译包。生产目标机通常更适合第 1 种方式。

## 4. 完全手动安装

```bash
sudo install -d -m 0755 /opt/iptables-web /var/lib/iptables-web
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

## 5. 检查服务与远端访问

```bash
sudo systemctl show iptables-web -p ExecStart -p Environment
sudo ss -lntp | grep 33801
curl -v http://127.0.0.1:33801/api/v1/health
curl -v http://$(hostname -I | awk '{print $1}'):33801/api/v1/health
```

如果本机地址 curl 成功而另一台机器浏览器失败，应用已经正常监听。继续检查现有网络路径：

```bash
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --list-all-zones
sudo iptables -nvL INPUT --line-numbers
```

只读检查不会修改规则。不要远程执行 flush，也不要临时加入宽范围 DROP/REJECT。

## 6. Docker 部署

```bash
docker compose up -d --build
```

需要 host network、NET_ADMIN、NET_RAW。端口自动发现优先读 Docker socket：

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

## 7. 升级

先备份 `/var/lib/iptables-web` 和系统管理页的“全部导出”，再在新包目录运行：

```bash
sudo bash install-binary.sh
```

安装器会重启现有服务。旧 firewalld 应用记录会备份后从应用数据移除，但主机 firewalld 配置保持不变。

## 8. 卸载

```bash
# 默认先精确删除界面托管规则，再卸载服务与文件
sudo bash uninstall.sh

# 兼容保留的完整清理别名；不会修改 firewalld
sudo bash uninstall.sh --purge
```

默认卸载和 `--purge` 都会删除 `rules.json` 中可精确重建的托管 packet 规则。两者都不调用 `firewall-cmd`、不 reload firewalld、不 flush 链、不删除未知外部规则。若必须保留运行规则，可显式使用 `--keep-rules`。
