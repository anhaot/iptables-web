# 文档导航

iptables-web 只通过 iptables/iptables-nft 管理 packet 规则。原生 nftables 运行后端已禁用；firewalld 不属于程序管理范围，可继续在程序外管理宿主机服务。

- [部署手册](deployment.md)：预编译包、源码、完全手动安装、升级与卸载。
- [配置说明](configuration.md)：环境变量、后端选择、数据文件。
- [API](api.md)：HTTP 接口与数据模型。
- [运维手册](operations.md)：备份、恢复、排障、安全清理。
- [架构](architecture.md)：组件、规则同步与 Docker 路径。
- [开发指南](development.md)：测试、构建与发布包验证。
- [安全说明](security.md)：权限、网络暴露与高风险操作。
- [路线图](roadmap.md)：当前边界与后续方向。

规则助手的生成和解读入口均保留，支持 iptables、ip6tables、nftables 和 firewalld；助手只输出文本，不执行命令。
