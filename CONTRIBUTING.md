# 贡献指南

感谢改进 iptables-web。防火墙变更可能中断主机网络，因此代码、测试和文档应作为同一项交付共同审查。

## 开始之前

1. 先阅读 [文档中心](docs/index.md)、[架构说明](docs/architecture.md) 和 [开发指南](docs/development.md)。
2. 确认问题在当前代码上可复现，并记录操作系统、防火墙后端、部署方式和最小复现步骤。
3. 安全问题不要在公开问题中包含真实 IP、规则集、密码、Token、API Key 或 `users.json`。

## 变更原则

- 保持默认监听 localhost、默认开启认证的安全基线。
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
go vet ./...
```

只改文档时也应检查相对链接、命令路径、环境变量名和 API 方法是否与实现一致。

## 提交说明

一次变更尽量只解决一个问题。说明中应包含：

- 为什么需要修改。
- 用户可见行为和兼容性影响。
- 如何验证，包括测试命令和结果。
- 涉及防火墙时的回滚方法。
- 涉及 UI 时的关键页面或交互变化。

## 文档维护

- 面向首次使用者的入口放在 `README.md`。
- 部署步骤放在 `docs/deployment.md`。
- 全量环境变量放在 `docs/configuration.md`。
- API 契约放在 `docs/api.md`。
- 日常操作和事故处置放在 `docs/operations.md`。
- 内部组件和设计边界放在 `docs/architecture.md`。
- 尚未实现的功能只放在 `docs/roadmap.md`，不要写成现有能力。

更详细的字段、路由和发布检查项见 [开发指南](docs/development.md)。
