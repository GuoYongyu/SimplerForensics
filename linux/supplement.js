(() => {
  const entries = [];
  const add = (category, name, syntax, description, examples, keywords, changes, source, sourceLabel, notes = '') => {
    entries.push({ id: `extra-${entries.length}`, category, name, syntax, description, examples, keywords, changes, source, sourceLabel, notes });
  };
  const runoob = (name) => [`https://www.runoob.com/linux/linux-comm-${name}.html`, '菜鸟教程 ↗'];
  const man = (name, section = 1) => [`https://man7.org/linux/man-pages/man${section}/${name}.${section}.html`, 'Linux 手册页 ↗'];
  const dockerDocs = ['https://docs.docker.com/reference/cli/docker/', 'Docker 官方文档 ↗'];
  const composeDocs = ['https://docs.docker.com/reference/cli/docker/compose/', 'Docker Compose 官方文档 ↗'];
  const panelDocs = {
    bt: ['https://www.aapanel.com/docs/', 'aaPanel 官方文档 ↗'],
    '1pctl': ['https://1panel.cn/docs/v2/installation/cli/', '1Panel 官方文档 ↗'],
    clpctl: ['https://www.cloudpanel.io/docs/v2/cloudpanel-cli/root-user-commands/', 'CloudPanel 官方文档 ↗'],
    openstack: ['https://docs.openstack.org/python-openstackclient/latest/cli/', 'OpenStack 官方文档 ↗']
  };

  // 命令的占位符约定：大写名称/尖括号表示需要替换为现场值。
  // Tutorial.md 的面板命令按原文收齐；版本号和面板菜单编号可能随版本变化。
  add('网站控制面板', 'bt <编号>', 'bt <编号>', '宝塔面板的数字菜单命令。下面列出 Tutorial.md 中出现的编号及用途；先核对当前版本菜单，部分操作会改配置、账户或服务。', ['bt', ...[
    ['bt 14', '查看面板登录信息', false], ['bt 1', '重启面板', true], ['bt 2', '停止面板', true], ['bt 3', '启动面板', true], ['bt 4', '重载面板配置', true],
    ['bt 5', '修改面板密码', true], ['bt 6', '修改面板用户名', true], ['bt 7', '修改数据库 root 密码', true], ['bt 8', '修改面板端口', true], ['bt 9', '清理面板缓存', true],
    ['bt 10', '清除登录限制', true], ['bt 12', '取消域名绑定限制', true], ['bt 13', '取消 IP 访问限制', true], ['bt 15', '清理系统临时文件或日志', true],
    ['bt 16', '修复并更新面板', true], ['bt 17', '切换日志压缩设置', true], ['bt 18', '切换自动备份设置', true], ['bt 22', '查看面板错误日志', false],
    ['bt 23', '关闭 BasicAuth', true], ['bt 24', '关闭动态口令验证', true], ['bt 25', '切换文件历史副本设置', true], ['bt 34', '更新面板', true], ['bt 36', '扫描并清理磁盘空间', true]
  ].map(([cmd]) => cmd)], '宝塔 BTPanel 登录信息 面板密码 端口 日志', true, ...panelDocs.bt, 'bt 14 查看账号信息等输出可能包含敏感数据；菜单编号以已安装版本显示为准。');

  const onePanel = [
    ['1pctl user-info', '查看面板地址和账户信息', false], ['1pctl version', '查看面板版本', false], ['1pctl status', '查看服务状态', false],
    ['1pctl start', '启动 1Panel', true], ['1pctl stop', '停止 1Panel', true], ['1pctl restart', '重启 1Panel', true], ['1pctl uninstall', '卸载面板', true],
    ['1pctl restore', '恢复面板数据', true], ['1pctl update username', '修改登录用户名', true], ['1pctl update password', '修改登录密码', true],
    ['1pctl update port', '修改面板端口', true], ['1pctl listen-ip ipv4', '切换监听为 IPv4', true], ['1pctl listen-ip ipv6', '切换监听为 IPv6', true],
    ['1pctl reset entrance', '重置安全入口配置', true], ['1pctl reset domain', '重置域名绑定', true], ['1pctl reset https', '重置 HTTPS 登录配置', true],
    ['1pctl reset ips', '重置授权 IP 限制', true], ['1pctl reset mfa', '重置两步验证', true], ['1pctl update', '更新面板（仅部分版本支持）', true],
    ['1panel app init', '初始化应用商店相关配置', true]
  ];
  onePanel.forEach(([cmd, description, changes]) => add('网站控制面板', cmd, cmd.replace(/\bipv[46]\b/, '<地址族>'), `${description}。该命令适用于已安装的 1Panel，参数和可用性以本机版本为准。`, [cmd], '1Panel 面板 用户名 密码 端口 安全入口 MFA', changes, ...panelDocs['1pctl'], 'user-info 可能输出登录敏感信息；修改认证或监听设置前确认仍能访问管理端。'));
  add('网站控制面板', 'systemctl start 1panel', 'systemctl start 1panel', '启动 1Panel systemd 服务。', ['systemctl start 1panel'], '1Panel 启动 systemd', true, ...man('systemctl', 1));

  const cloudPanel = [
    ['clpctl -V', '查看 clpctl 版本', false], ['clpctl list', '列出当前版本支持的子命令', false], ['clpctl help', '查看命令帮助', false],
    ['clpctl help cloudpanel:info', '查看 cloudpanel:info 子命令帮助', false], ['clpctl cloudpanel:info', '查看 CloudPanel 信息', false],
    ['clp-update', '运行 CloudPanel 官方升级脚本', true], ['systemctl restart cloudpanel', '重启 CloudPanel 服务', true],
    ['systemctl status cloudpanel', '查看 CloudPanel 服务状态', false], ['journalctl -u cloudpanel -f', '实时查看 CloudPanel 服务日志', false]
  ];
  cloudPanel.forEach(([cmd, description, changes]) => {
    const root = cmd.startsWith('clp') ? 'clpctl' : cmd.startsWith('journalctl') ? 'journalctl' : 'systemctl';
    const docs = root === 'clpctl' ? panelDocs.clpctl : man(root, root === 'journalctl' ? 1 : 1);
    add('网站控制面板', cmd, cmd, `${description}。CloudPanel 命令及服务名会随版本变化，先通过帮助确认本机语法。`, [cmd], 'CloudPanel clpctl 面板 服务 日志 升级', changes, ...docs, '面板升级或服务重启会改变运行状态；维护前准备管理端回退方式。');
  });

  // OpenStack examples from Tutorial.md; NAME/NETWORK/IP 等是云资源标识占位符。
  const openstack = [
    ['openstack --version', '查看客户端版本', false], ['openstack catalog list', '查看服务目录及 endpoint', false], ['openstack compute service list', '查看计算服务', false],
    ['openstack network agent list', '查看网络代理状态', false], ['openstack user list', '列出用户', false], ['openstack project list', '列出项目/租户', false],
    ['openstack role list', '列出角色', false], ['openstack image list', '列出镜像', false], ['openstack server list', '列出云主机', false],
    ['openstack server create --image IMAGE --flavor FLAVOR --network NET NAME', '按镜像、规格和网络创建云主机', true], ['openstack server show NAME', '查看云主机详情', false],
    ['openstack server stop NAME', '停止云主机', true], ['openstack server start NAME', '启动云主机', true], ['openstack server reboot NAME', '重启云主机', true],
    ['openstack server delete NAME', '删除云主机', true], ['openstack flavor list', '列出云主机规格', false], ['openstack network list', '列出网络', false],
    ['openstack subnet list', '列出子网', false], ['openstack router list', '列出路由器', false], ['openstack floating ip create NETWORK', '从指定网络申请浮动 IP', true],
    ['openstack server add floating ip SERVER IP', '将浮动 IP 绑定到云主机', true], ['openstack security group list', '列出安全组', false],
    ['openstack volume list', '列出云硬盘', false], ['openstack volume create --size 50 NAME', '创建 50 GiB 云硬盘', true],
    ['openstack server add volume SERVER VOLUME', '把云硬盘挂载到云主机', true], ['openstack console log show NAME', '查看云主机控制台日志', false],
    ['openstack console url show NAME', '查看实例控制台访问地址', false]
  ];
  openstack.forEach(([cmd, description, changes]) => add('云平台与基础设施', cmd, cmd, `${description}。先加载当前项目的 OpenStack 凭据；NAME、NETWORK、SERVER、VOLUME 等需要替换成实际资源名或 ID。`, [cmd], 'OpenStack 云主机 云硬盘 网络 浮动 IP 安全组', changes, ...panelDocs.openstack, changes ? '创建、启动、停止、重启、绑定和删除会影响云资源或服务。执行前复核项目、区域和资源 ID。' : '加载凭据可使用 source admin-openrc；不要把凭据文件或控制台 URL 分享给无关人员。'));
  add('云平台与基础设施', 'openstack-service status', 'openstack-service status', '查看 OpenStack 服务管理脚本报告的组件状态。', ['openstack-service status'], 'OpenStack 服务状态 运维', false, ...panelDocs.openstack);
  add('云平台与基础设施', 'openstack-service restart', 'openstack-service restart <组件>', '重启指定 OpenStack 服务组件。组件示例包括 glance、nova、neutron、cinder。', ['openstack-service restart glance'], 'OpenStack 组件 glance nova neutron cinder 重启', true, ...panelDocs.openstack, '重启会中断对应服务；该脚本并非所有发行版都提供。');
  add('云平台与基础设施', 'source admin-openrc', 'source <凭据文件>', '在当前 shell 中载入 OpenStack 环境变量。凭据文件常见于 /root/admin-openrc.sh。', ['source admin-openrc'], 'OpenStack 认证 凭据 环境变量', false, ...panelDocs.openstack, '不要将凭据内容、密码或 token 粘贴到公开位置。');

  // Middleware commands and safe checks.
  const nginxActions = [
    ['systemctl start nginx', '启动 Nginx 服务', true], ['systemctl stop nginx', '停止 Nginx 服务', true], ['systemctl restart nginx', '重启 Nginx 服务', true],
    ['systemctl reload nginx', '平滑重载 Nginx 配置', true], ['systemctl status nginx', '查看 Nginx 服务状态', false],
    ['systemctl enable nginx', '设为开机自启', true], ['systemctl disable nginx', '取消开机自启', true], ['nginx', '以前台/默认方式启动 Nginx', true],
    ['nginx -c /path/to/nginx.conf', '指定主配置文件启动或检查 Nginx', true], ['nginx -t', '检查配置语法及引用文件', false],
    ['nginx -T', '打印合并 include 后的完整配置', false], ['nginx -s reload', '平滑重载 Nginx 配置', true], ['nginx -s quit', '优雅停止 Nginx', true],
    ['nginx -s stop', '立即停止 Nginx', true], ['nginx -s reopen', '重新打开日志文件', true], ['nginx -v', '查看版本号', false], ['nginx -V', '查看版本和编译选项', false],
    ['tail -f /var/log/nginx/access.log', '实时跟踪访问日志', false], ['tail -f /var/log/nginx/error.log', '实时跟踪错误日志', false], ['journalctl -u nginx -f', '实时跟踪 systemd 服务日志', false]
  ];
  nginxActions.forEach(([cmd, description, changes]) => add('Web 服务与中间件', cmd.replace(/^sudo\s+/, ''), cmd, `${description}。Nginx 配置文件常见于 /etc/nginx/nginx.conf；执行重载前先运行 nginx -t。`, [cmd], 'Nginx 网站 服务配置 访问日志 错误日志', changes, 'https://nginx.org/en/docs/switches.html', 'Nginx 官方文档', changes ? '检查命令本身不会更改配置；启动、停止、重载或日志重开会改变运行状态。' : '完整配置输出可能包含路径、域名或内部地址。'));

  const apacheActions = [
    ['sudo systemctl start httpd', '启动 Apache（常见于 RHEL/Fedora）', true], ['sudo systemctl start apache2', '启动 Apache（常见于 Debian/Ubuntu）', true],
    ['sudo systemctl stop httpd', '停止 Apache', true], ['sudo systemctl restart httpd', '重启 Apache', true], ['sudo systemctl reload httpd', '平滑重载 Apache', true],
    ['systemctl status httpd', '查看 Apache 服务状态', false], ['sudo systemctl enable httpd', '设置 Apache 开机自启', true], ['sudo systemctl disable httpd', '取消 Apache 开机自启', true],
    ['sudo apachectl start', '通过控制脚本启动 Apache', true], ['sudo apachectl stop', '通过控制脚本停止 Apache', true], ['sudo apachectl restart', '通过控制脚本重启 Apache', true],
    ['sudo apachectl graceful', '让 Apache 完成当前请求后平滑重启', true], ['sudo apachectl configtest', '检查 Apache 配置语法', false],
    ['sudo httpd -t', '检查 httpd 配置语法', false], ['httpd -v', '查看 Apache 版本', false], ['httpd -V', '查看版本及编译参数', false],
    ['httpd -M', '列出已加载模块', false], ['sudo tail -f /var/log/httpd/access_log', '跟踪访问日志（常见 RHEL 路径）', false],
    ['sudo tail -f /var/log/httpd/error_log', '跟踪错误日志（常见 RHEL 路径）', false], ['sudo journalctl -u httpd -f', '跟踪 systemd 服务日志', false]
  ];
  apacheActions.forEach(([cmd, description, changes]) => add('Web 服务与中间件', cmd.replace(/^sudo\s+/, ''), cmd, `${description}。不同发行版可能使用 httpd 或 apache2 作为服务名；修改后先运行 apachectl configtest。`, [cmd], 'Apache httpd apache2 网站 日志 配置', changes, 'https://httpd.apache.org/docs/2.4/programs/httpd.html', 'Apache 官方文档', '路径与服务名依发行版而异；查看日志前确认该主机实际配置的日志路径。'));

  // Docker examples from Tutorial.md, with explicit explanations for placeholders.
  const dockerCommands = [
    ['docker --version', 'docker --version', '查看 Docker CLI 版本', false], ['docker info', 'docker info', '查看 Docker Engine、存储驱动和资源信息', false],
    ['docker pull', 'docker pull <镜像[:标签]>', '从镜像仓库拉取镜像。nginx:latest 中 latest 是标签；生产环境建议使用明确版本。', true, ['docker pull nginx', 'docker pull nginx:latest']],
    ['docker images', 'docker images', '列出本地镜像及标签、ID、大小。', false],
    ['docker build', 'docker build -t <镜像名:标签> <构建目录>', '读取构建目录中的 Dockerfile 并构建镜像；`.` 表示当前目录。', true, ['docker build -t app:latest .', 'docker build -t myapp:1.0 .']],
    ['docker rmi', 'docker rmi <镜像名:标签>', '删除本地镜像；镜像被容器引用时通常无法删除。', true, ['docker rmi nginx', 'docker rmi myapp:1.0']],
    ['docker run', 'docker run [选项] <镜像>', '基于镜像创建并启动新容器。`--name web` 指定容器名；`-p 主机端口:容器端口` 发布端口；`-v 主机路径:容器路径` 挂载目录。', true, ['docker run -d --name web -p 8080:80 nginx', 'docker run -d --name web nginx', 'docker run -d -p 8080:80 nginx', 'docker run -d -v /opt/html:/usr/share/nginx/html nginx']],
    ['docker ps', 'docker ps [-a]', '查看运行中容器；`-a` 也显示已退出容器。输出中的 NAMES 可用于后续容器命令。', false, ['docker ps', 'docker ps -a']],
    ['docker start', 'docker start <容器名或 ID>', '启动已停止的容器。示例中的 `web` 是容器名，可替换为 `docker ps -a` 输出中的实际 NAME 或 CONTAINER ID。', true, ['docker start web']],
    ['docker stop', 'docker stop <容器名或 ID>', '向容器发送停止信号并等待其退出。`web` 是示例容器名，应替换为目标容器的 NAME 或 ID。', true, ['docker stop web']],
    ['docker kill', 'docker kill <容器名或 ID>', '立即向容器发送终止信号；可能来不及完成应用清理。', true, ['docker kill web']],
    ['docker restart', 'docker restart <容器名或 ID>', '重启指定容器；将短暂中断容器内服务。', true, ['docker restart web']],
    ['docker rm', 'docker rm [-f] <容器名或 ID>', '删除容器；`-f` 会强制停止运行中的容器后删除。先核对容器和挂载卷。', true, ['docker rm web', 'docker rm -f web']],
    ['docker exec', 'docker exec -it <容器名或 ID> <命令>', '在运行中的容器执行交互命令。示例 `web` 是容器名；容器没有 bash 时可改用 `/bin/sh`。', true, ['docker exec -it web /bin/bash']],
    ['docker logs', 'docker logs [-f] [--tail 行数] <容器名或 ID>', '读取容器标准输出和错误日志；`-f` 实时跟踪。`web` 是容器名示例。', false, ['docker logs web', 'docker logs -f --tail 100 web', 'docker logs -f web']],
    ['docker port', 'docker port <容器名或 ID>', '查看容器已发布的端口映射；`web` 是容器名示例。', false, ['docker port web']],
    ['docker inspect', 'docker inspect <容器名、ID、镜像或网络>', '查看 JSON 配置，包括容器网络、挂载点、端口和状态。示例 `web` 是容器名。', false, ['docker inspect web']],
    ['docker cp', 'docker cp <容器>:<容器路径> <主机路径>', '在宿主机和容器之间复制文件。`web:/app/index.html` 表示从名为 web 的容器取文件。', true, ['docker cp web:/app/index.html ./index.html']],
    ['docker stats', 'docker stats [容器名或 ID]', '实时查看容器 CPU、内存、网络和块 I/O 使用量。', false],
    ['docker system prune', 'docker system prune [选项]', '清理未使用的 Docker 资源；可能删除停止的容器、未使用网络和构建缓存。执行前先查看 `docker system df`。', true],
    ['docker tag', 'docker tag <源镜像:标签> <新镜像:标签>', '为已有镜像增加一个标签，不会复制镜像层。', true, ['docker tag myapp:1.0 myapp:latest']],
    ['docker save', 'docker save -o <归档文件> <镜像:标签>', '将镜像保存为 tar 归档，供离线传输。', true, ['docker save -o myapp.tar myapp:latest']],
    ['docker load', 'docker load -i <归档文件>', '从 docker save 生成的归档载入镜像。', true, ['docker load -i myapp.tar']],
    ['docker network ls', 'docker network ls', '列出 Docker 网络。', false], ['docker network create', 'docker network create <网络名>', '创建自定义 Docker 网络。示例 mynet 是网络名。', true, ['docker network create mynet']],
    ['docker network inspect', 'docker network inspect <网络名或 ID>', '查看 Docker 网络配置及连接的容器；mynet 是网络名示例。', false, ['docker network inspect mynet']]
  ];
  dockerCommands.forEach(([name, syntax, description, changes, examples]) => {
    const root = name.startsWith('docker compose') ? 'compose' : 'docker';
    add('容器与 Docker', name, syntax, description, examples || [name], 'Docker 容器 镜像 网络 端口 挂载 日志 资源', Boolean(changes), ...(root === 'compose' ? composeDocs : dockerDocs));
  });

  const composeCommands = [
    ['docker compose up -d', '后台创建并启动 Compose 服务', true], ['docker compose ps', '查看 Compose 项目容器状态', false],
    ['docker compose logs -f', '实时跟踪所有 Compose 服务日志', false], ['docker compose restart web', '重启名为 web 的 Compose 服务', true],
    ['docker compose stop', '停止当前 Compose 项目服务但保留容器', true], ['docker compose down', '停止并移除 Compose 项目的容器和网络', true],
    ['docker compose exec web /bin/bash', '在名为 web 的 Compose 服务容器执行交互 shell', true], ['docker compose build', '根据 Compose 配置重新构建镜像', true]
  ];
  composeCommands.forEach(([cmd, description, changes]) => add('容器与 Docker', cmd.split(' ').slice(0, 3).join(' '), cmd, `${description}。这里的 web 是 compose.yaml/docker-compose.yml 中的服务名；用 docker compose ps 查看实际服务名。`, [cmd], 'Docker Compose 服务 容器 日志', changes, ...composeDocs));

  // Additional practical network/port commands beyond the two source files.
  const networkCommands = [
    ['ip -br addr', '简洁查看网卡和地址', false], ['ip link show', '查看网卡链路状态', false], ['ip route get 1.1.1.1', '查看发往目标地址时使用的路由和出口网卡', false],
    ['ss -lntp', '查看 TCP 监听端口和关联进程', false], ['ss -lnup', '查看 UDP 监听端口和关联进程', false], ['ss -tan state established', '查看已建立的 TCP 连接', false],
    ['ss -s', '查看套接字统计摘要', false], ['sudo lsof -nP -iTCP -sTCP:LISTEN', '列出 TCP 监听端口和进程，禁止名称解析以便快速查看', false],
    ['sudo fuser -v 8080/tcp', '查看哪个进程正在使用 TCP 8080 端口', false], ['sudo lsof -nP -i :8080', '查询使用 8080 端口的进程', false],
    ['curl -v telnet://127.0.0.1:8080', '用 curl 检查本机 TCP 端口连接', false], ['nc -vz -w 3 127.0.0.1 8080', '以 3 秒超时检查 TCP 端口是否可连接', false],
    ['sudo tcpdump -ni any port 8080', '抓取所有接口上与 8080 端口相关的数据包', true], ['sudo ufw status numbered', '查看带编号的 UFW 规则', false],
    ['sudo ufw allow 8080/tcp', '添加 UFW TCP 8080 放行规则', true], ['sudo ufw delete allow 8080/tcp', '删除对应的 UFW 放行规则', true],
    ['sudo firewall-cmd --list-ports', '列出 firewalld 当前区域开放的端口', false], ['sudo firewall-cmd --list-services', '列出 firewalld 当前区域放行的服务', false],
    ['sudo firewall-cmd --add-port=8080/tcp --permanent', '永久添加 firewalld TCP 8080 规则', true], ['sudo firewall-cmd --reload', '重载 firewalld 永久规则', true],
    ['dig +short A example.com', '只输出域名的 IPv4 A 记录结果', false], ['getent ahosts example.com', '通过系统解析配置查询主机名地址', false],
    ['curl -I --max-time 10 https://example.com', '限时查看网站 HTTP 响应头', false], ['openssl s_client -connect example.com:443 -servername example.com', '查看 TLS 握手、证书和服务端响应', false],
    ['ip neigh show', '查看内核邻居表中的 IP 与链路层地址', false], ['nmcli device status', '查看 NetworkManager 管理的网卡状态', false],
    ['nmcli connection show', '列出 NetworkManager 保存的网络连接配置', false], ['sudo nmcli connection up <连接名>', '启用指定 NetworkManager 连接', true]
  ];
  networkCommands.forEach(([cmd, description, changes]) => {
    const root = cmd.startsWith('sudo ') ? cmd.split(' ')[1] : cmd.split(' ')[0];
    const docs = root === 'ufw' ? ['https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html', 'Ubuntu 手册页 ↗']
      : root === 'firewall-cmd' ? ['https://firewalld.org/documentation/man-pages/firewall-cmd.html', 'firewalld 官方文档 ↗']
        : root === 'nmcli' ? ['https://networkmanager.dev/docs/api/latest/nmcli.html', 'NetworkManager 官方文档 ↗']
          : ['ss', 'lsof', 'curl', 'dig', 'ip', 'netstat', 'tcpdump'].includes(root) ? [...runoob(root)]
            : man(root, ['tcpdump', 'lsof', 'fuser'].includes(root) ? 8 : 1);
    add('网络与端口', cmd.replace(/^sudo\s+/, ''), cmd, description, [cmd], '端口 端口占用 监听 网卡 防火墙 路由 DNS 网络连接 网站证书', changes, ...docs);
  });

  // Tutorial.md examples whose command identity should be directly searchable.
  add('网络与端口', 'ifup', 'ifup <网卡名>', '启动指定网络接口；该工具在部分现代发行版已被 NetworkManager 或 systemd-networkd 替代。', ['ifup eth0'], '启动网卡 ifup 网卡名', true, 'https://manpages.debian.org/bookworm/ifupdown/ifup.8.en.html', 'Linux 手册页 ↗', '请以实际接口名替换 eth0；先查看 ip link。');
  add('网络与端口', 'dhclient', 'dhclient -v [网卡名]', '以详细模式发起 DHCP 地址租约；可能更改网卡 IP 和路由状态。', ['dhclient -v'], 'DHCP 获取 IP 网卡', true, 'https://man7.org/linux/man-pages/man8/dhclient.8.html', 'Linux 手册页 ↗', '接口管理工具和 DHCP 客户端依发行版而异。');
  add('网络与端口', 'ifconfig', 'ifconfig [网卡]', '查看传统网络接口信息；新系统通常优先使用 `ip addr`。', ['ifconfig'], '网卡 IP 地址 旧工具', false, ...runoob('ifconfig'));

  const tutorialExtra = [
    ['compgen -c', 'compgen -c', '列出当前 Bash shell 能识别的命令名称。', 'Shell 命令列表 builtin', false, 'https://www.gnu.org/software/bash/manual/bash.html', 'GNU Bash 手册 ↗'],
    ['mount /sdb2 /mnt/xxx', 'mount <设备或分区> <挂载点>', '把已确认的分区挂载到指定目录。取证镜像应先评估只读挂载选项。', 'mount 分区 磁盘 取证', true, ...runoob('mount')],
    ['ip a', 'ip addr', '查看网卡和 IP 地址。', '网卡 IP 地址', false, 'https://man7.org/linux/man-pages/man8/ip-address.8.html', 'Linux 手册页 ↗'],
    ['vim', 'vim <文件>', '使用 Vim 编辑文本文件；退出前确认是否保存更改。', '文本编辑器 vi vim', true, 'https://www.runoob.com/linux/linux-vim.html', '菜鸟教程 ↗'],
    ['ufw disable', 'ufw disable', '关闭 UFW 管理的防火墙规则。主机可能立即暴露到外部网络。', '防火墙 关闭 ufw', true, 'https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html', 'Ubuntu 手册页 ↗'],
    ['systemctl stop firewalld', 'systemctl stop firewalld', '立即停止 firewalld 服务；会改变防火墙运行状态。', '防火墙 firewalld 停止', true, 'https://www.freedesktop.org/software/systemd/man/latest/systemctl.html', 'systemd 官方手册 ↗'],
    ['dhclient -v', 'dhclient -v [网卡名]', '以详细模式申请 DHCP 地址租约；可能改变网卡地址和路由状态。', 'DHCP 获取地址 网络', true, 'https://man7.org/linux/man-pages/man8/dhclient.8.html', 'Linux 手册页 ↗'],
    ['ss -tuln', 'ss -tuln', '列出 TCP/UDP 监听端口，以数字形式显示地址和端口。', '端口占用 查端口 TCP UDP', false, ...runoob('ss')],
    ['ss -tulnp', 'ss -tulnp', '查看 TCP/UDP 监听端口及关联进程；显示进程通常需要管理员权限。', '端口占用 进程监听', false, ...runoob('ss')],
    ['netstat -tuln', 'netstat -tuln', '传统 net-tools 写法：查看 TCP/UDP 监听端口。', '端口占用 老命令 net-tools', false, ...runoob('netstat')],
    ['netstat -tulnp', 'netstat -tulnp', '传统 net-tools 写法：查看监听端口及关联进程。', '端口占用 进程监听', false, ...runoob('netstat')],
    ['sudo -i', 'sudo -i', '通过 sudo 打开 root 登录 shell，并加载 root 的登录环境。用 whoami 确认当前身份；完成管理操作后输入 exit 返回原用户。', 'root 管理员 shell 切换用户 提权 身份', true, ...runoob('sudo'), ['sudo -i', 'whoami', 'exit']],
    ['uname -a', 'uname -a', '查看内核、主机和 CPU 架构信息。', 'Linux 版本 内核 架构', false, ...runoob('uname')],
    ['fdisk -l', 'fdisk -l [设备]', '只读列出磁盘分区表。查看时不要进入交互式分区编辑。', '磁盘分区 设备', false, ...runoob('fdisk')],
    ['df -h', 'df -h [路径]', '以易读单位显示文件系统容量和使用率。', '磁盘剩余空间 空间不足', false, ...runoob('df')],
    ['du -sh /path/to/dir/', 'du -sh <目录>', '汇总查看目录占用的磁盘空间。', '文件夹大小 目录占用 磁盘空间', false, ...runoob('du')],
    ['sudo command', 'sudo <命令>', '以获授权的管理员身份运行单条命令，不会切换当前 shell 身份。', 'root 管理员权限 用户切换 提权', true, ...runoob('sudo')],
    ['su username', 'su <用户名>', '切换到指定用户；username 是需要替换的用户名。默认 shell 通常不会加载该用户完整登录环境。', '用户切换 root 普通用户', true, ...runoob('su')],
    ['su - username', 'su - <用户名>', '切换到指定用户并加载其登录环境；将 username 替换为实际账户名。', '用户切换 登录环境 root', true, ...runoob('su'), ['su - analyst', 'whoami']],
    ['su root', 'su root', '切换到 root 用户；此方式通常需要 root 账户密码。若没有 root 密码但有 sudo 授权，可用 sudo -i。', '用户切换 root 管理员', true, ...runoob('su')],
    ['sudo -u username command', 'sudo -u <用户名> <命令>', '只以指定用户身份执行一条命令，不改变当前 shell。替换用户名和要运行的命令。', 'sudo 用户切换 指定用户运行命令', true, ...runoob('sudo'), ['sudo -u www-data id', 'sudo -u analyst whoami']],
    ['sudo -iu username', 'sudo -iu <用户名>', '通过 sudo 切换到指定用户的登录 shell，并加载其登录环境；输入 exit 返回原 shell。', 'sudo 用户切换 登录环境', true, ...runoob('sudo'), ['sudo -iu www-data', 'whoami', 'exit']],
    ['whoami', 'whoami', '显示当前 shell 的有效用户名；切换用户或使用 sudo 后可用它确认当前身份。', '当前用户 身份 用户切换 root', false, ...runoob('whoami')],
    ['bt xxx', 'bt <编号>', '宝塔菜单命令的通用形式。编号与功能可能随版本改变，先运行 bt 查看本机菜单。', '宝塔 面板 管理命令', true, ...panelDocs.bt],
    ['1pctl xxx', '1pctl <子命令>', '1Panel 命令的通用形式；用 1pctl --help 或官方文档确认当前版本支持的子命令。', '1Panel 面板 管理命令', true, ...panelDocs['1pctl']],
    ['clpctl xxx', 'clpctl <子命令>', 'CloudPanel 命令的通用形式；先运行 clpctl help 查询本机支持的操作。', 'CloudPanel 面板 管理命令', true, ...panelDocs.clpctl],
    ['onestack xxx', 'onestack <子命令>', '用户资料中的 OpenStack 管理命令形式；此包装命令依具体环境而异。', 'OpenStack 管理命令', false, ...panelDocs.openstack],
    ['docker system df', 'docker system df', '汇总 Docker 镜像、容器和卷占用空间，可用于清理前检查。', 'Docker 磁盘空间 占用', false, ...dockerDocs],
    ['docker exec -it web /bin/sh', 'docker exec -it <容器名> /bin/sh', '在运行容器内打开 shell。web 是示例容器名；没有 bash 的镜像可尝试 /bin/sh。', 'Docker 容器 shell 进入', true, ...dockerDocs],
    ['docker-compose.yml', 'docker-compose.yml', 'Docker Compose 的常见项目定义文件名；新版也常用 compose.yaml。', 'Docker Compose 配置文件 YAML', false, ...composeDocs]
  ];
  tutorialExtra.forEach(([cmd, syntax, description, keywords, changes, source, sourceLabel, examples]) => add(
    /^(sudo -i|sudo command|sudo -u |sudo -iu |su |whoami)/.test(cmd) ? '用户与权限' : /^(mount|fdisk|df|du)/.test(cmd) ? '磁盘与归档' : /^(ufw|systemctl stop firewalld|ifup|dhclient|ifconfig|ss |netstat|ip )/.test(cmd) ? '网络与端口' : /^(docker|docker-compose)/.test(cmd) ? '容器与 Docker' : /^(bt|1pctl|clpctl)/.test(cmd) ? '网站控制面板' : /^onestack/.test(cmd) ? '云平台与基础设施' : /^vim\b/.test(cmd) ? '文件与目录' : /^uname/.test(cmd) ? '系统与服务' : '命令与帮助',
    cmd, syntax, description, examples || [cmd], keywords, changes, source, sourceLabel
  ));
  add('网络与端口', 'firewalld', 'firewalld / firewall-cmd', 'firewalld 是常见 Linux 防火墙服务；用 firewall-cmd 查看、增删区域规则。', ['sudo firewall-cmd --list-all'], '防火墙 firewalld firewall-cmd', false, 'https://firewalld.org/documentation/', 'firewalld 官方文档 ↗');

  // UUID 与摘要校验：读取既有标识、按规则生成/计算 UUID，以及计算文件摘要。
  // 注意：磁盘/固件 UUID 通常由文件系统或固件写入，不能从内容反推；
  // 只有 v3/v5 UUID 是由“命名空间 + 名称”经哈希计算出来的。
  add('UUID 与标识', 'uuidgen', 'uuidgen [-r|-t|-6|-7]', '生成新的 UUID。默认在随机源可用时生成随机 UUID（v4）；`-t` 生成时间型 UUID，`-r` 强制随机，较新的 util-linux 还支持可排序的 `-6`/`-7`。', ['uuidgen', 'uuidgen -r', 'uuidgen -t'], 'UUID 生成 uuid生成 随机 uuid计算 UUID计算 v4 v1 v6 v7 标识', false, ...man('uuidgen', 1));
  add('UUID 与标识', 'uuidgen --md5', 'uuidgen --md5 --namespace <命名空间> --name <名称>', '按 RFC 4122 用 MD5 计算 v3 UUID：同一命名空间和名称总得到同一结果，适合可复现的标识。它只对“命名空间 + 名称”做哈希，不会读取块设备或固件信息；命名空间可用 @dns、@url、@oid、@x500 或一个 UUID。', ['uuidgen --md5 --namespace @dns --name example.com'], 'UUID 计算 uuid计算 uuid生成 MD5 v3 name-based 命名空间 可复现 哈希', false, ...man('uuidgen', 1), 'v3/v5 的结果可预测，不要当作随机值、密码或密钥。');
  add('UUID 与标识', 'uuidgen --sha1', 'uuidgen --sha1 --namespace <命名空间> --name <名称>', '按 RFC 4122 用 SHA-1 计算 v5 UUID：同一命名空间和名称总得到同一结果。相比 v3 使用 SHA-1，但仍不适合作为密码或密钥。', ['uuidgen --sha1 --namespace @dns --name www.example.com'], 'UUID 计算 uuid计算 uuid生成 SHA1 v5 name-based 命名空间 可复现 哈希', false, ...man('uuidgen', 1), '需要 util-linux 的 uuidgen；输出是确定性的哈希结果，不是随机 UUID。');
  add('UUID 与标识', 'uuidparse', 'uuidparse [-J|-n|-r] [-o 列] <UUID>', '解析 UUID 并显示 variant、类型/版本和时间等信息；`-J` 输出 JSON，`-n` 去掉表头，`-r` 使用原始输出，`-o` 选择 UUID、VARIANT、TYPE、TIME 等列。', ['uuidparse 3f2504e0-4f89-11d3-9a0c-0305e82c3301', 'uuidparse -J 3f2504e0-4f89-11d3-9a0c-0305e82c3301', 'uuidparse -n -o UUID,TYPE,VARIANT,TIME 3f2504e0-4f89-11d3-9a0c-0305e82c3301'], 'UUID 解析 uuid解析 版本 variant 类型 校验 uuidparse', false, ...man('uuidparse', 1), '列名和可用类型随 util-linux 版本略有差异，可先用 uuidparse --help 查看。');
  add('UUID 与标识', 'cat /proc/sys/kernel/random/uuid', 'cat /proc/sys/kernel/random/uuid', '从内核随机源读取一个新的随机 UUID；每次读取都会得到不同值，适合脚本快速生成 v4 UUID，但不会持久保存。', ['cat /proc/sys/kernel/random/uuid'], 'UUID 生成 uuid生成 随机 uuid计算 内核 proc', false, ...man('random', 4));

  add('UUID 与标识', 'lsblk -o UUID', 'lsblk -o NAME,FSTYPE,UUID,PARTUUID,MOUNTPOINT', '列出块设备名、文件系统类型、文件系统 UUID、分区 UUID（PARTUUID）和挂载点；`lsblk -f` 也会显示文件系统 UUID，`-o` 更适合筛选和脚本处理。', ['lsblk -f', 'lsblk -o NAME,FSTYPE,UUID,PARTUUID,MOUNTPOINT', 'lsblk -o NAME,UUID,MOUNTPOINT'], '磁盘uuid 磁盘 UUID 分区uuid 分区 UUID PARTUUID 文件系统uuid lsblk 块设备', false, ...man('lsblk', 8));
  add('UUID 与标识', 'ls -l /dev/disk/by-uuid/', 'ls -l /dev/disk/by-uuid/', '查看 udev 维护的 UUID 到设备节点的符号链接；可用它确认某个文件系统 UUID 当前对应哪个磁盘分区。', ['ls -l /dev/disk/by-uuid/', 'ls -l /dev/disk/by-partuuid/', 'readlink -f "/dev/disk/by-uuid/<UUID>"'], '磁盘uuid 磁盘 UUID 分区uuid 设备映射 by-uuid by-partuuid udev 符号链接', false, ...man('udev', 7), '链接由 udev 根据当前设备生成；UUID 被修改或设备未接入时链接会变化或消失。');
  add('UUID 与标识', 'findfs', 'findfs UUID=<UUID>', '按 UUID、PARTUUID、LABEL 或 PARTLABEL 查找对应的设备节点；适合在挂载前把 UUID 解析成 /dev/... 路径。', ['sudo findfs UUID=<UUID>', 'sudo findfs PARTUUID=<PARTUUID>', 'sudo findfs LABEL=DATA'], '磁盘uuid 分区uuid PARTUUID UUID 查找 设备 findfs', false, ...man('findfs', 8), '需要读取设备信息的权限；结果只代表当前系统识别到的设备。');
  add('UUID 与标识', 'sfdisk --part-uuid/--disk-id', 'sfdisk --part-uuid <设备> <分区号>', '读取 GPT 分区 UUID 或磁盘标识；`--part-uuid` 不带新值时打印分区 UUID，`--disk-id` 打印 GPT 磁盘 UUID（MBR 为整数）。指定新值会修改分区表。', ['sudo sfdisk --part-uuid /dev/sda 1', 'sudo sfdisk --disk-id /dev/sda'], '磁盘uuid 分区uuid PARTUUID GPT 磁盘标识 sfdisk', false, ...man('sfdisk', 8), '示例只读取；给 --part-uuid/--disk-id 追加新值会修改分区表，可能影响挂载和引导，操作前备份。');
  add('UUID 与标识', 'cryptsetup luksUUID', 'cryptsetup luksUUID <设备>', '读取 LUKS 加密设备的 UUID；`luksDump` 还可查看 cipher、key slot 等头部信息。注意它是 LUKS 容器 UUID，不是容器内文件系统的 UUID。', ['sudo cryptsetup luksUUID /dev/sda2', 'sudo cryptsetup luksDump /dev/sda2'], '磁盘uuid LUKS 加密 UUID cryptsetup 分区', false, ...man('cryptsetup-luksUUID', 8), '需要 root 或相应设备权限；只查询不会解密或修改 LUKS 头部。');
  add('UUID 与标识', 'swaplabel', 'swaplabel <设备>', '显示 swap 分区的 UUID 和标签；加 `-U <UUID>` 或 `-L <标签>` 会修改 swap 头部，属于变更操作。', ['sudo swaplabel /dev/sda3'], '磁盘uuid swap UUID 交换分区 swaplabel', false, ...man('swaplabel', 8), '只读查询不会影响正在使用的 swap；使用 -U/-L 修改前应确认 fstab 和 initramfs 中的引用。');
  add('UUID 与标识', 'mdadm --detail', 'mdadm --detail <设备>', '查看 Linux 软件 RAID 阵列详情，包括阵列 UUID、成员盘和状态；`--detail --scan` 可输出适合写入 mdadm.conf 的形式。', ['sudo mdadm --detail /dev/md0', 'sudo mdadm --detail --scan'], '磁盘uuid RAID UUID mdadm 阵列 成员盘', false, ...man('mdadm', 8), '仅适用于 mdadm 管理的软件 RAID；需要 root 且系统已安装 mdadm。');
  add('UUID 与标识', 'btrfs filesystem show', 'btrfs filesystem show [路径|UUID|设备]', '查看 Btrfs 文件系统的 UUID（fsid）、设备成员和空间概况；可按挂载点、UUID 或设备过滤。', ['sudo btrfs filesystem show', 'sudo btrfs filesystem show /mnt/data'], '磁盘uuid Btrfs UUID fsid 文件系统 btrfs', false, ...man('btrfs-filesystem', 8), '需要 btrfs-progs；Btrfs 的 fsid 与分区 PARTUUID 不是同一个标识。');
  add('UUID 与标识', 'pvs/vgs/lvs', 'pvs -o pv_name,pv_uuid', '查看 LVM 的物理卷（PV）、卷组（VG）和逻辑卷（LV）UUID；对应命令分别是 pvs、vgs、lvs，均可用 `-o` 选择字段。', ['sudo pvs -o pv_name,pv_uuid', 'sudo vgs -o vg_name,vg_uuid', 'sudo lvs -o lv_name,lv_uuid'], '磁盘uuid LVM UUID PV VG LV pvs vgs lvs', false, ...man('pvs', 8), '需要安装 LVM2；LVM UUID 与文件系统 UUID、分区 UUID 属于不同层次。');
  add('UUID 与标识', 'findmnt -o UUID', 'findmnt -o TARGET,SOURCE,FSTYPE,UUID', '列出已挂载文件系统的挂载点、设备、类型和 UUID；也可用 `-S "UUID=<UUID>"` 按 UUID 查找当前挂载点。', ['findmnt -o TARGET,SOURCE,FSTYPE,UUID', 'findmnt -S "UUID=<UUID>"'], '挂载 uuid 文件系统uuid 磁盘uuid findmnt 挂载点', false, ...man('findmnt', 8));
  add('UUID 与标识', 'udevadm info --query=property', 'udevadm info --query=property --name=<设备>', '查询 udev 数据库中设备的属性：ID_FS_UUID 是文件系统 UUID，ID_PART_ENTRY_UUID 是分区表 UUID（PARTUUID）。', ['udevadm info --query=property --name=/dev/sda1', 'udevadm info --query=property --name=/dev/sda1 | grep -E "ID_FS_UUID|ID_PART_ENTRY_UUID"'], '磁盘uuid 分区uuid PARTUUID 文件系统uuid udev 属性 设备', false, ...man('udevadm', 8), '输出可能包含序列号、厂商等硬件信息；公开前先筛选敏感字段。');
  add('UUID 与标识', 'tune2fs -l', 'tune2fs -l <设备>', '读取 ext2/ext3/ext4 超级块信息，包括 Filesystem UUID、卷标和特性；只读查询不会修改文件系统。', ['sudo tune2fs -l /dev/sda1 | grep -i "Filesystem UUID"'], '磁盘uuid 文件系统uuid ext4 ext3 ext2 tune2fs 超级块 UUID', false, ...man('tune2fs', 8), '部分信息需要 root；不要对已挂载设备执行修改类选项，查询时只使用 `-l`。');
  add('UUID 与标识', 'dumpe2fs -h', 'dumpe2fs -h <设备>', '以只读方式输出 ext 文件系统超级块摘要，其中包含 UUID；适合与 tune2fs 的结果交叉核对。', ['sudo dumpe2fs -h /dev/sda1 | grep -i uuid'], '磁盘uuid 文件系统uuid ext 超级块 dumpe2fs UUID', false, ...man('dumpe2fs', 8), '需要读取块设备的权限；只读查看时不要使用会写回文件系统的修复选项。');
  add('UUID 与标识', 'xfs_admin -u', 'xfs_admin -u <设备>', '输出 XFS 文件系统的 UUID；XFS 的 UUID 不会像 ext 一样随意修改，变更前必须卸载并评估挂载、引导和备份影响。', ['sudo xfs_admin -u /dev/sda1'], '磁盘uuid 文件系统uuid XFS xfs_admin UUID', false, ...man('xfs_admin', 8));
  add('UUID 与标识', 'mount UUID=', 'mount [-o 选项] UUID="<UUID>" <挂载点>', '按文件系统 UUID 挂载设备，避免设备名变化导致挂错盘；取证场景可同时加 `-o ro` 只读挂载。', ['sudo mount UUID="<UUID>" /mnt/evidence', 'sudo mount -o ro UUID="<UUID>" /mnt/evidence'], '挂载 uuid 磁盘uuid 文件系统 只读 取证 fstab', true, ...man('mount', 8), '挂载会改变系统挂载状态；永久挂载应写入 /etc/fstab，并用 findmnt --verify 检查。');
  add('UUID 与标识', 'tune2fs -U', 'tune2fs -U <random|UUID> <设备>', '修改 ext 文件系统 UUID；`random` 生成新值，也可指定 UUID。修改后必须同步更新 /etc/fstab、引导参数和其他引用，否则可能无法启动或挂载。', ['sudo tune2fs -U random /dev/sda1', 'sudo tune2fs -U "$NEW_UUID" /dev/sda1'], '修改uuid 修改 UUID 磁盘uuid 文件系统 ext4 风险', true, ...man('tune2fs', 8), '高风险操作：先备份并卸载目标文件系统，不要把 UUID 改成与现有设备冲突的值。');
  add('UUID 与标识', 'xfs_admin -U', 'xfs_admin -U <generate|UUID> <设备>', '修改 XFS 文件系统 UUID；`generate` 生成新值。通常要求先卸载，修改后同样要更新 fstab、引导配置和其他引用。', ['sudo xfs_admin -U generate /dev/sda1'], '修改uuid 修改 UUID 磁盘uuid XFS 文件系统 风险', true, ...man('xfs_admin', 8), '高风险操作：先确认设备、备份并卸载；不要在有挂载或写入活动的文件系统上执行。');
  add('磁盘与归档', 'parted -l', 'parted -l', '列出所有磁盘的分区表和分区边界；只查看时使用 `-l`，交互式 parted 可能修改分区。', ['sudo parted -l'], '磁盘 分区 GPT MBR 分区表 容量', false, ...man('parted', 8), '不同版本输出略有差异；修改分区前先备份并确认设备名。');
  add('磁盘与归档', 'smartctl -a', 'smartctl -a <设备>', '读取硬盘 SMART 健康、型号、序列号、温度和属性；`-x` 输出更完整的信息，`-H` 只看健康结论。', ['sudo smartctl -a /dev/sda', 'sudo smartctl -H /dev/sda'], '磁盘健康 SMART 序列号 硬盘 检测 温度', false, 'https://manpages.debian.org/bookworm/smartmontools/smartctl.8.en.html', 'Debian 手册页 ↗', '需要 smartmontools 和相应权限；USB 桥接或 RAID 控制器可能不支持直通 SMART。');
  add('磁盘与归档', 'fsck -n', 'fsck -n <设备>', '以只读方式检查文件系统并回答 no，不做修复；不要在已读写挂载的文件系统上运行修复型 fsck。', ['sudo fsck -n /dev/sda1'], '文件系统 检查 修复 只读 fsck', false, ...man('fsck', 8), '不同文件系统的 fsck 前端行为不同；`-n` 只用于检查，修复前先卸载或使用只读快照。');
  add('磁盘与归档', 'mkfs.ext4', 'mkfs.ext4 <设备>', '在指定设备上创建 ext4 文件系统；会覆盖原有文件系统和数据，执行前必须确认设备名。', ['sudo mkfs.ext4 /dev/sdb1'], '格式化 创建文件系统 ext4 磁盘 风险 mkfs', true, ...man('mke2fs', 8), '高风险操作：会销毁目标设备上的数据。先备份、确认设备，并检查是否已挂载。');
  add('磁盘与归档', 'mkswap', 'mkswap <设备>', '把分区或文件初始化为 swap 区域；`-U <UUID>` 可指定 UUID，之后还需 swapon 才会启用。会覆盖目标区域原有内容。', ['sudo mkswap /dev/sda3', 'sudo mkswap -U "$NEW_UUID" /dev/sda3'], 'swap 交换分区 格式化 UUID 风险 mkswap', true, ...man('mkswap', 8), '高风险操作：先确认设备没有被挂载或使用；启用 swap 后检查 /etc/fstab 和权限设置。');
  add('UUID 与标识', 'dmidecode -s system-uuid', 'dmidecode -s system-uuid', '从 SMBIOS/DMI 读取系统（整机）UUID，常用于资产标识或授权绑定；虚拟机可能返回全 0、全 F 或不稳定的值。', ['sudo dmidecode -s system-uuid', 'sudo dmidecode -s baseboard-serial-number', 'sudo dmidecode -s system-serial-number'], '硬件uuid 硬件 UUID 系统uuid 整机uuid SMBIOS DMI 机器码 资产 序列号', false, 'https://manpages.debian.org/bookworm/dmidecode/dmidecode.8.en.html', 'Debian 手册页 ↗', '需要 root；不同厂商写入的质量不一，不能把它当作绝对可靠的唯一标识。');
  add('UUID 与标识', 'cat /sys/class/dmi/id/product_uuid', 'cat /sys/class/dmi/id/product_uuid', '从 sysfs 读取 DMI 产品 UUID，不依赖 dmidecode；该文件通常只有 root 可读。', ['sudo cat /sys/class/dmi/id/product_uuid', 'sudo cat /sys/class/dmi/id/board_serial', 'sudo cat /sys/class/dmi/id/product_serial'], '硬件uuid 硬件 UUID 系统uuid DMI sysfs product_uuid 主板序列号 机器码', false, 'https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-firmware-dmi-tables', 'Linux 内核文档 ↗', '容器或部分虚拟机中可能不存在该文件；值由固件提供。');
  add('UUID 与标识', 'dmidecode -t system', 'dmidecode -t system', '查看 SMBIOS 系统信息，包括制造商、产品名、序列号和 UUID，适合与资产记录核对；`-t baseboard` 可查看主板信息。', ['sudo dmidecode -t system', 'sudo dmidecode -t baseboard'], '硬件信息 硬件uuid 系统uuid 序列号 资产管理 SMBIOS DMI', false, 'https://manpages.debian.org/bookworm/dmidecode/dmidecode.8.en.html', 'Debian 手册页 ↗', '输出可能包含序列号、资产标签等敏感硬件信息。');
  add('UUID 与标识', 'cat /etc/machine-id', 'cat /etc/machine-id', '读取本机 machine-id；systemd 系统安装时生成，常用于日志、授权和数据关联。它不是硬件 UUID，克隆系统可能得到相同值。', ['cat /etc/machine-id', 'systemd-id128 machine-id -u'], '机器id 机器 ID machine-id 系统标识 硬件uuid 授权', false, ...man('machine-id', 5), '不要把它当作硬件序列号；容器内可能继承宿主机或单独生成。');
  add('UUID 与标识', 'systemd-id128 machine-id', 'systemd-id128 machine-id -u', '把 /etc/machine-id 输出为带连字符的 UUID；加 `-a <APP_ID>` 可计算应用专用 ID，结果可复现。', ['systemd-id128 machine-id -u', 'systemd-id128 machine-id -u -a "$APP_ID"'], '机器id UUID systemd id128 uuid计算 应用专用 计算', false, ...man('systemd-id128', 1), 'machine-id 与 app-id 的组合结果是稳定哈希，不是硬件 UUID。');
  add('UUID 与标识', 'dbus-uuidgen --get', 'dbus-uuidgen --get', '读取 D-Bus 机器 UUID（通常来自 /var/lib/dbus/machine-id 或 /etc/machine-id）；`--ensure` 可在缺失时创建。', ['dbus-uuidgen --get'], '机器id UUID dbus machine-id 系统标识', false, 'https://dbus.freedesktop.org/doc/dbus-uuidgen.1.html', 'D-Bus 文档 ↗', '`--ensure` 会写入系统文件，属于变更操作；本条目只做查询。');

  add('哈希与校验', 'md5sum', 'md5sum [选项] <文件>', '计算文件的 MD5 摘要（128 位）；常用于下载校验和取证初筛。MD5 已不适合作为抗碰撞的安全签名，安全场景优先 SHA-256。', ['md5sum evidence.img', 'md5sum file1 file2', 'md5sum --tag evidence.img'], 'MD5 计算 md5计算 md5摘要 md5校验 哈希 摘要 校验 完整性 取证 文件', false, ...man('md5sum', 1));
  add('哈希与校验', 'md5sum -c', 'md5sum -c <校验文件>', '按校验文件逐行验证文件 MD5：匹配输出 OK，不匹配输出 FAILED；`--quiet` 只显示失败项。', ['md5sum -c checksums.md5', 'md5sum --quiet -c checksums.md5'], 'MD5 校验 md5校验 验证 完整性 下载 哈希 文件', false, ...man('md5sum', 1), '校验文件中的路径相对于当前目录；MD5 只能证明内容一致，不能证明来源可信。');
  add('哈希与校验', 'find + md5sum', 'find <目录> -type f -print0 | xargs -0 md5sum > <清单文件>', '批量计算目录下所有普通文件的 MD5 并写入清单；`-print0` 与 `-0` 能正确处理含空格或换行的文件名。', ['find /evidence -type f -print0 | xargs -0 md5sum > /analysis/md5.txt'], '批量 MD5 计算 哈希 清单 取证 目录 校验', true, ...man('find', 1), '会创建清单文件；先确认输出路径和磁盘空间，取证时不要把结果写回证据目录。');
  add('哈希与校验', 'openssl dgst -md5', 'openssl dgst -md5 <文件>', '用 OpenSSL 计算摘要；示例为 MD5，也可把 `-md5` 换成 `-sha1`、`-sha256` 或 `-sha512`。输出格式与 md5sum 不同，适合交叉核对。', ['openssl dgst -md5 evidence.img', 'openssl dgst -sha256 evidence.img', 'openssl md5 evidence.img'], 'MD5 计算 md5计算 md5摘要 SHA256 SHA512 哈希 OpenSSL 摘要 校验', false, 'https://docs.openssl.org/3.0/man1/openssl-dgst/', 'OpenSSL 官方文档 ↗');
  add('哈希与校验', 'sha1sum', 'sha1sum [选项] <文件>', '计算 SHA-1 摘要；SHA-1 已不具备抗碰撞安全性，适合兼容旧清单或非对抗性校验，安全场景应改用 SHA-256。', ['sha1sum evidence.img', 'sha1sum -c SHA1SUMS'], 'SHA1 计算 sha1计算 sha1校验 哈希 摘要 校验 完整性', false, ...man('sha1sum', 1));
  add('哈希与校验', 'sha224sum', 'sha224sum [选项] <文件>', '计算 SHA-224 摘要；属于 SHA-2 家族，适合与只接受 224 位摘要的旧系统对接。', ['sha224sum evidence.img', 'sha224sum -c SHA224SUMS'], 'SHA224 计算 sha224计算 sha224校验 哈希 摘要 校验 完整性', false, ...man('sha224sum', 1));
  add('哈希与校验', 'sha384sum', 'sha384sum [选项] <文件>', '计算 SHA-384 摘要；属于 SHA-2 家族，常用于需要比 SHA-256 更长摘要的场景。', ['sha384sum evidence.img', 'sha384sum -c SHA384SUMS'], 'SHA384 计算 sha384计算 sha384校验 哈希 摘要 校验 完整性', false, ...man('sha384sum', 1));
  add('哈希与校验', 'sha512sum', 'sha512sum [选项] <文件>', '计算 SHA-512 摘要，输出 128 位十六进制字符；适合需要更强摘要的完整性核对。', ['sha512sum evidence.img', 'sha512sum -c SHA512SUMS'], 'SHA512 计算 sha512计算 sha512校验 哈希 摘要 校验 完整性', false, ...man('sha512sum', 1));
  add('哈希与校验', 'b2sum', 'b2sum [选项] <文件>', '计算 BLAKE2b 摘要（默认 512 位）；速度通常快于 SHA-2，适合大文件完整性校验。', ['b2sum evidence.img', 'b2sum -c B2SUMS'], 'BLAKE2 b2sum b2sum计算 b2sum校验 计算 哈希 摘要 校验 大文件', false, ...man('b2sum', 1), 'BLAKE2 不是 SHA 系列；保存校验文件时同时记录所用算法，避免后续误用。');

  // Hardware inventory, security auditing, process and performance commands.
  add('系统与服务', 'lscpu', 'lscpu', '查看 CPU 架构、核心数、线程、NUMA 和虚拟化标志等信息。', ['lscpu', 'lscpu -e'], 'CPU 架构 核心 线程 硬件 虚拟化', false, ...man('lscpu', 1));
  add('系统与服务', 'lsusb', 'lsusb [选项]', '列出 USB 总线和设备；`-t` 显示树状拓扑，`-v` 显示详细描述符（输出可能较长）。', ['lsusb', 'lsusb -t', 'lsusb -v -d 1234:5678'], 'USB 设备 硬件 总线 描述符', false, ...man('lsusb', 8), '`-v` 可能输出大量描述符；示例中的设备 ID 需要替换。');
  add('系统与服务', 'lspci', 'lspci [选项]', '列出 PCI 设备；`-nnk` 同时显示设备 ID 和内核驱动，适合排查网卡、显卡和存储控制器。', ['lspci', 'lspci -nnk', 'lspci -v'], 'PCI 硬件 网卡 显卡 驱动 设备', false, ...man('lspci', 8));
  add('系统与服务', 'lsmod', 'lsmod', '列出已加载的内核模块及引用计数；可结合 `modinfo <模块>` 查看模块详情。', ['lsmod', 'lsmod | grep nf_conntrack', 'modinfo nf_conntrack'], '内核模块 驱动 硬件 lsmod', false, ...man('lsmod', 8));
  add('系统与服务', 'lshw', 'lshw -quiet -c system', '查看硬件清单和系统概要，包括制造商、型号、序列号等；`-short` 可快速浏览。', ['sudo lshw -quiet -c system', 'sudo lshw -short'], '硬件 序列号 型号 资产 lshw 主板', false, 'https://manpages.debian.org/bookworm/lshw/lshw.1.en.html', 'Debian 手册页 ↗', '需要安装 lshw；普通用户可能看不到完整序列号，输出也可能包含敏感硬件信息。');

  add('网络与端口', 'iptables -L', 'iptables -L -n -v', '列出 IPv4 防火墙规则和计数器；`-S` 以命令形式输出规则。查看通常需要 root。', ['sudo iptables -L -n -v', 'sudo iptables -S'], '防火墙 iptables 规则 端口 网络', false, ...man('iptables', 8), '修改规则会立即改变防火墙行为；远程操作前先确认不会锁断 SSH。');
  add('网络与端口', 'nft list ruleset', 'nft list ruleset', '列出 nftables 当前规则集；`nft list tables` 可先查看有哪些表。', ['sudo nft list ruleset', 'sudo nft list tables'], '防火墙 nftables nft 规则 网络', false, 'https://manpages.debian.org/bookworm/nftables/nft.8.en.html', 'Debian 手册页 ↗', '修改 nftables 规则会改变防火墙行为；远程操作前准备回退方式。');
  add('系统与服务', 'lastb', 'lastb [选项]', '读取 /var/log/btmp，查看失败的登录尝试；日志轮转或清理会影响结果。', ['sudo lastb', 'sudo lastb -Fai | head -n 50'], '登录失败 暴力破解 审计 取证 btmp', false, ...man('lastb', 1), '需要读取 btmp 的权限；某些系统可能未记录或已清空该文件。');
  add('系统与服务', 'lastlog', 'lastlog [选项]', '按用户查看最后一次登录时间和来源；`-u <用户>` 只看指定账户。', ['lastlog', 'sudo lastlog -u root'], '最后登录 用户 审计 取证 lastlog', false, ...man('lastlog', 8), '数据来自 /var/log/lastlog；从未登录的账户通常显示为 Never logged in。');
  add('系统与服务', 'w', 'w [选项]', '查看当前登录用户、来源、登录时间和正在执行的命令；`-h` 不显示表头。', ['w', 'w -h'], '当前登录 用户 会话 活动 审计', false, ...man('w', 1));
  add('网络与端口', 'ssh-keygen', 'ssh-keygen [选项]', '生成、查看或删除 SSH 密钥和 known_hosts 条目。`-t ed25519` 生成 Ed25519 密钥，`-lf` 查看公钥指纹，`-R` 删除主机旧密钥。', ['ssh-keygen -t ed25519 -a 100', 'ssh-keygen -lf ~/.ssh/id_ed25519.pub', 'ssh-keygen -R host.example.com'], 'SSH 密钥 指纹 known_hosts 公钥 私钥', true, ...man('ssh-keygen', 1), '生成或删除密钥会写入文件；私钥不要上传或公开，删除 known_hosts 前确认主机指纹。');

  add('用户与权限', 'setfacl', 'setfacl [选项] 文件', '设置文件或目录的 POSIX ACL；`-m` 修改条目，`-x` 删除条目，`-b` 清除扩展 ACL。', ['setfacl -m u:alice:rw /srv/report.txt', 'getfacl /srv/report.txt', 'setfacl -x u:alice /srv/report.txt'], 'ACL 权限 访问控制 setfacl 用户', true, ...man('setfacl', 1), '修改 ACL 会改变访问权限；先用 getfacl 记录原状态，避免误删其他条目。');
  add('用户与权限', 'getcap/setcap', 'getcap -r <路径>', '查看或设置文件 capabilities；`getcap -r /` 递归查找，`setcap cap_net_raw+ep <文件>` 赋予能力。', ['sudo getcap -r / 2>/dev/null', 'getcap /usr/bin/ping', 'sudo setcap cap_net_raw+ep /usr/local/bin/mytool'], 'capabilities 权限 提权 getcap setcap 安全', true, ...man('getcap', 8), 'setcap 会改变可执行文件权限，可能形成提权风险；修改前记录原值并评估最小权限。');
  add('系统与服务', 'getenforce/sestatus', 'getenforce', '查看 SELinux 当前模式（Enforcing/Permissive/Disabled）和详细状态；`sestatus -v` 还会显示策略与布尔值信息。', ['getenforce', 'sestatus', 'sudo sestatus -v'], 'SELinux 安全 状态 强制 模式 sestatus getenforce', false, ...man('sestatus', 8), '仅适用于启用 SELinux 的系统；修改模式或策略前先评估访问控制影响。');
  add('系统与服务', 'aa-status', 'aa-status', '查看 AppArmor 状态、已加载配置文件和受约束进程；通常需要 root 才能看到完整信息。', ['sudo aa-status'], 'AppArmor 安全 状态 配置文件 进程', false, 'https://manpages.debian.org/bookworm/apparmor/aa-status.8.en.html', 'Debian 手册页 ↗', '仅适用于启用 AppArmor 的系统；不同发行版的 profile 路径和输出略有差异。');
  add('系统与服务', 'ausearch/aureport', 'ausearch -m <类型> -ts recent', '查询和汇总 Linux 审计日志；`ausearch` 按条件查事件，`aureport` 生成登录、认证、文件访问等摘要。', ['sudo ausearch -m avc -ts recent', 'sudo aureport --auth', 'sudo aureport -f'], '审计 audit 日志 ausearch aureport 取证 认证', false, ...man('ausearch', 8), '需要 auditd 正在运行并已配置规则；日志可能被轮转或清理，取证时应先只读保全。');

  add('系统与服务', 'iotop', 'iotop [选项]', '按进程查看磁盘 I/O 带宽和 swap 活动；`-o` 只显示有 I/O 的进程，`-P` 按进程汇总。', ['sudo iotop -oPa'], '磁盘 I/O 进程 性能 iotop', false, ...man('iotop', 8), '需要 root 和 iotop 软件包；容器或受限内核可能无法读取全部进程。');
  add('系统与服务', 'mpstat', 'mpstat [选项] [间隔 [次数]]', '查看每个 CPU 核心的使用率统计；`-P ALL` 显示所有核心。通常由 sysstat 提供。', ['mpstat -P ALL 1 5'], 'CPU 性能 核心 使用率 mpstat', false, ...man('mpstat', 1), '需要 sysstat 软件包；首次使用前确认采样间隔和次数，避免长时间占用终端。');
  add('系统与服务', 'sar', 'sar [选项] [间隔 [次数]]', '查看历史或实时系统性能统计，包括 CPU、内存、网络和磁盘；数据通常由 sysstat 采集。', ['sar -u 1 5', 'sar -n DEV 1 5', 'sar -r'], '性能 历史 CPU 内存 网络 sar sysstat', false, ...man('sar', 1), '历史数据依赖 sysstat 服务已启用；不同版本的字段和采集配置可能不同。');
  add('系统与服务', 'strace', 'strace [选项] 命令', '跟踪进程的系统调用和信号；`-p <PID>` 附加到运行中进程，`-c` 汇总调用耗时。', ['strace -f -p <PID>', 'strace -c ls /tmp'], '系统调用 调试 进程 strace 排障', false, ...man('strace', 1), '附加跟踪需要权限；输出可能包含路径、参数和敏感数据，且会拖慢目标进程。');
  add('系统与服务', 'pkill', 'pkill [选项] 模式', '按名称或命令行模式向进程发送信号；`-f` 匹配完整命令行，`-u` 限定用户。默认信号通常是 TERM。', ['pkill -f nginx', 'pkill -TERM -u analyst'], '进程 结束 停止 pkill 信号', true, ...man('pkill', 1), '会终止匹配的进程；先用 pgrep 确认匹配范围，避免误杀。');
  add('系统与服务', 'killall', 'killall [选项] 进程名', '按进程名向所有匹配进程发送信号；默认通常为 TERM，`-9` 强制终止。', ['killall nginx', 'killall -9 process-name'], '进程 结束 停止 killall 信号', true, ...man('killall', 1), '会作用于所有同名进程；先确认进程名和目标，避免影响其他服务。');
  add('命令与帮助', 'nohup', 'nohup 命令 [参数] &', '让命令忽略挂断信号并在退出 shell 后继续运行；通常配合重定向保存输出。', ['nohup ./backup.sh > backup.log 2>&1 &'], '后台 长期运行 退出 shell nohup 进程', true, ...man('nohup', 1), '会在当前目录创建 nohup.out（若未重定向）；确认输出路径和磁盘空间。');

  window.LINUX_COMMANDS = (window.LINUX_COMMANDS || []).concat(entries);
})();
