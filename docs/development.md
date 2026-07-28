# 开发指南

## 本地测试

开发环境使用 no-op 后端，避免触碰主机防火墙：

```bash
DEV_MODE=true RULES_FILE=/tmp/iptables-web-rules.json USERS_FILE=/tmp/iptables-web-users.json go run ./cmd/server
```

不要在共享或远程机器上用真实后端做破坏性测试。

## 测试

```bash
GOCACHE=/tmp/iptables-web-go-cache go test ./...
node scripts/ui-logic-test.js
```

测试覆盖模型校验、排序风险、启停/同步基础逻辑、助手生成与解读、Docker IPv4/IPv6 解析、认证和备份结构。测试不应调用 firewall-cmd 或修改真实规则。

## 前端嵌入

Go 二进制嵌入 `assets/web`。构建脚本会先把 `web` 同步到该目录，避免出现源码页面已更新但预编译二进制仍是旧界面的情况。

## 发布预编译包

```bash
VERSION=<版本号> bash scripts/build-package.sh
bash scripts/verify-package.sh dist/iptables-web-<版本号>-linux-amd64.tar.gz
```

包必须包含二进制、`install-binary.sh`、`uninstall.sh`、README、docs、VERSION 和 SHA-256。离线验证会确认：

- 二进制支持 `--version`；
- 默认外部监听配置已嵌入；
- packet-only 规则页已嵌入；
- Docker IPv4/IPv6 分类已嵌入；
- 规则助手生成/解读入口都在；
- 卸载支持托管规则清理和 purge。

验证不会启动服务或访问防火墙。

`dist/` 是本地构建目录，不提交到 Git。通过校验的压缩包和 SHA-256 应上传到与版本 Tag 对应的 GitHub Release。
