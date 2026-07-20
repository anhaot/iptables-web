// ====== iptables / nftables 链用途说明 ======

const FirewallHelp = {
  chainDescriptions: {
    INPUT: '进入本机进程的流量，例如 SSH、Web 管理端口和宿主机服务。',
    FORWARD: '经过本机转发但不终止于本机的流量，Docker 容器转发通常经过这里。',
    OUTPUT: '由本机进程主动发出的流量。',
    DOCKER: 'Docker 自动维护的端口映射链，不建议直接手工调整。',
    DOCKER_USER: 'Docker 提供给管理员的自定义转发规则入口，早于 Docker 自动放行规则。',
    'DOCKER-USER': 'Docker 提供给管理员的自定义转发规则入口，早于 Docker 自动放行规则。'
  },
  chainTitle(name) {
    return this.chainDescriptions[name] || '自定义链；具体用途取决于跳转到该链的上游规则。';
  }
};
