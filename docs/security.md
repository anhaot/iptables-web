# 安全说明

iptables-web 需要操作 packet 防火墙，属于高权限管理服务。

## 网络暴露

默认监听 `0.0.0.0:33801`，因此进程接受所有本机 IPv4 网卡的连接。安装器不会放行端口；管理员应使用外部 firewalld、云安全组、VPN 或反向代理限制来源。服务没有内置 TLS，跨不可信网络应使用 HTTPS 反向代理。

保持 `AUTH_ENABLED=true`。首次账号是 `admin` / `admin123`，登录后必须立即修改。API Key 不应写入公开脚本、日志或仓库。

## 防火墙边界

程序只管理 IPv4 packet 规则，不读取或修改 firewalld；IPv6 托管 CRUD 会被明确拒绝，助手仍可生成供人工审核的 ip6tables 命令。安装和卸载脚本也不会执行 `firewall-cmd` 或 reload firewalld。程序不会在新安装时添加拒绝规则或 flush 链。

`users.json` 和 `rules.json` 使用 `0600`，安装器创建的数据目录使用 `0700`。删除用户、修改密码或调整角色后，现有会话会立即撤销或按当前角色重新校验。

## Docker

容器部署使用 host network 与 NET_ADMIN/NET_RAW，意味着容器能影响宿主机网络。只使用受信任镜像与只读 Docker socket，保护数据卷和宿主机访问权限。

## 高风险操作

- 新增宽范围 DROP/REJECT；
- 把兜底拒绝排到白名单 ACCEPT 前；
- 恢复完整规则集；
- flush iptables/nftables；
- 删除管理端口放行；
- 在远程会话中更改默认策略。

执行前应备份、保留带外控制台并确认回滚。程序 UI 会阻止部分明显的白名单排序错误，但不能理解所有外部规则、路由和网络命名空间。

## 卸载

默认卸载按 `rules.json` 精确删除界面托管规则；兼容保留的 `--purge` 也不会修改 firewalld。两者都不 flush 未知规则。清理失败时默认保留程序与数据，避免丢失恢复依据。
