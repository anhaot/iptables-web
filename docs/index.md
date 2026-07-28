# 文档导航

iptables-web 只通过 iptables/iptables-nft 管理 packet 规则。原生 nftables 运行后端已禁用；firewalld 不属于程序管理范围，可继续在程序外管理宿主机服务。

- [部署与配置](deployment.md)：安装方式、环境变量、网络安全、升级与卸载。
- [架构与实现](architecture.md)：组件、规则同步、数据文件、认证和 Docker 路径。
- [运维与排障](operations.md)：日常检查、审计、备份恢复、清理和故障处置。
- [API](api.md)：HTTP 接口与数据模型。
- [路线图](roadmap.md)：当前边界与后续方向。
- [贡献指南](../CONTRIBUTING.md)：开发环境、测试、前端同步和发布流程。

规则助手的生成和解读入口均保留，支持 iptables、ip6tables、nftables 和 firewalld；助手只输出文本，不执行命令。
