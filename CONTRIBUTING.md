# 贡献指南

感谢改进 iptables-web。防火墙变更可能中断主机网络，因此代码、测试和文档应作为同一项交付共同审查。

## 开始之前

1. 先阅读[文档中心](docs/index.md)和[架构与实现](docs/architecture.md)。
2. 确认问题在当前代码上可复现，并记录操作系统、防火墙后端、部署方式和最小复现步骤。
3. 安全问题不要在公开问题中包含真实 IP、规则集、密码、Token、API Key 或 `users.json`。

## 变更原则

- 保持默认开启认证、安装器不自动修改 firewalld 的安全基线。
- 不使用 shell 拼接任何来自请求的数据；外部命令必须使用独立参数。
- 不 flush 非本程序独占的系统链。
- 规则写入失败时保持 JSON 管理态与内核运行态尽可能一致。
- 保持旧 `rules.json` 和 `users.json` 可加载；破坏性格式变更必须提供迁移方案。
- 新行为必须补充测试和对应文档。
- 不提交真实运行数据、密钥、构建产物或本地临时文件。

## 本地验证

普通开发使用 no-op 防火墙后端：

```bash
mkdir -p data
DEV_MODE=true \
RULES_FILE=./data/rules.json \
USERS_FILE=./data/users.json \
go run ./cmd/server
```

提交前运行：

```bash
gofmt -w <changed-go-files>
GOCACHE=/tmp/iptables-web-go-cache go test ./...
go test -race ./...
go vet ./...
node scripts/ui-logic-test.js
bash scripts/integration-smoke.sh
```

端到端烟测强制使用回环监听和 `DEV_MODE`，不会修改本机防火墙；需要 `curl` 和 `jq`。涉及真实 iptables 的测试必须放在独立网络命名空间或专用测试机中，不能复用开发机现有规则。

只改文档时也应检查相对链接、命令路径、环境变量名和 API 方法是否与实现一致。

## 前端资源

可直接调试的前端源码位于 `web/`，Go 二进制嵌入 `assets/web/`。构建脚本会先同步这两个目录。手工修改后应检查：

```bash
diff -qr web assets/web
```

不要只更新其中一份，否则源码页面和发布二进制会出现差异。

## 构建发布包

```bash
VERSION=0.1.0 bash scripts/build-package.sh
bash scripts/verify-package.sh dist/iptables-web-0.1.0-linux-amd64.tar.gz
```

构建脚本会同步前端、运行测试、生成 Linux amd64 二进制、安装脚本、文档、版本清单和 SHA-256。离线验证不会启动服务或访问防火墙。

正式版本使用 `v主版本.次版本.修订版本` Tag。推送版本 Tag 后，GitHub Actions 自动构建并创建 Release。`dist/` 只用于本地构建，不提交到 Git。

## 提交说明

一次变更尽量只解决一个问题。说明中应包含：

- 为什么需要修改。
- 用户可见行为和兼容性影响。
- 如何验证，包括测试命令和结果。
- 涉及防火墙时的回滚方法。
- 涉及 UI 时的关键页面或交互变化。

## 文档维护

- 面向首次使用者的入口放在 `README.md`。
- 安装、环境变量和网络安全配置放在 `docs/deployment.md`。
- API 契约放在 `docs/api.md`。
- 日常操作、备份恢复和事故处置放在 `docs/operations.md`。
- 内部组件、数据文件和设计边界放在 `docs/architecture.md`。
- 尚未实现的功能只放在 `docs/roadmap.md`，不要写成现有能力。

## 仓库边界

- 提交源码、测试、脚本、用户文档和必要的文档截图。
- 不提交 `bin/`、`dist/`、浏览器测试输出、覆盖率文件、本地审查报告或运行数据。
- 发布压缩包和校验和上传到 GitHub Releases，不放入源码分支。
- `.env`、Token、API Key、`users.json`、`audit.jsonl` 和真实防火墙备份不得提交。
