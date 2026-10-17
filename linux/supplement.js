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
  add('网站控制面板', 'bt', 'bt <编号>', '宝塔面板的数字菜单命令。下面列出 Tutorial.md 中出现的编号及用途；先核对当前版本菜单，部分操作会改配置、账户或服务。', ['bt', ...[
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
  openstack.forEach(([cmd, description, changes]) => add('云平台与基础设施', cmd.split(' ').slice(0, 2).join(' '), cmd, `${description}。先加载当前项目的 OpenStack 凭据；NAME、NETWORK、SERVER、VOLUME 等需要替换成实际资源名或 ID。`, [cmd], 'OpenStack 云主机 云硬盘 网络 浮动 IP 安全组', changes, ...panelDocs.openstack, changes ? '创建、启动、停止、重启、绑定和删除会影响云资源或服务。执行前复核项目、区域和资源 ID。' : '加载凭据可使用 source admin-openrc；不要把凭据文件或控制台 URL 分享给无关人员。'));
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
  nginxActions.forEach(([cmd, description, changes]) => add('Web 服务与中间件', cmd.split(' ').slice(0, 2).join(' '), cmd, `${description}。Nginx 配置文件常见于 /etc/nginx/nginx.conf；执行重载前先运行 nginx -t。`, [cmd], 'Nginx 网站 服务配置 访问日志 错误日志', changes, 'https://nginx.org/en/docs/switches.html', 'Nginx 官方文档', changes ? '检查命令本身不会更改配置；启动、停止、重载或日志重开会改变运行状态。' : '完整配置输出可能包含路径、域名或内部地址。'));

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
  apacheActions.forEach(([cmd, description, changes]) => add('Web 服务与中间件', cmd.split(' ').slice(-2).join(' '), cmd, `${description}。不同发行版可能使用 httpd 或 apache2 作为服务名；修改后先运行 apachectl configtest。`, [cmd], 'Apache httpd apache2 网站 日志 配置', changes, 'https://httpd.apache.org/docs/2.4/programs/httpd.html', 'Apache 官方文档', '路径与服务名依发行版而异；查看日志前确认该主机实际配置的日志路径。'));

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
    add('网络与端口', root, cmd, description, [cmd], '端口 端口占用 监听 网卡 防火墙 路由 DNS 网络连接 网站证书', changes, ...docs);
  });

  // Tutorial.md examples whose command identity should be directly searchable.
  add('网络与端口', 'ifup', 'ifup <网卡名>', '启动指定网络接口；该工具在部分现代发行版已被 NetworkManager 或 systemd-networkd 替代。', ['ifup eth0'], '启动网卡 ifup 网卡名', true, 'https://manpages.debian.org/bookworm/ifupdown/ifup.8.en.html', 'Linux 手册页 ↗', '请以实际接口名替换 eth0；先查看 ip link。');
  add('网络与端口', 'dhclient', 'dhclient -v [网卡名]', '以详细模式发起 DHCP 地址租约；可能更改网卡 IP 和路由状态。', ['dhclient -v'], 'DHCP 获取 IP 网卡', true, 'https://man7.org/linux/man-pages/man8/dhclient.8.html', 'Linux 手册页 ↗', '接口管理工具和 DHCP 客户端依发行版而异。');
  add('网络与端口', 'ifconfig', 'ifconfig [网卡]', '查看传统网络接口信息；新系统通常优先使用 `ip addr`。', ['ifconfig'], '网卡 IP 地址 旧工具', false, ...runoob('ifconfig'));

  // Make every distinct archive command from Tutorial.md searchable and copyable.
  const archiveExamples = [
    ['zip', 'zip -r file.zip dir/', '递归压缩目录为 ZIP；-r 表示递归。', true], ['zip', 'zip file.zip file1 file2', '把多个文件压缩到 ZIP。', true],
    ['unzip', 'unzip file.zip', '解压 ZIP 到当前目录。', true], ['unzip', 'unzip file.zip -d /path/to/dir', '解压 ZIP 到指定目录，目录不存在时通常会创建。', true],
    ['unzip', 'unzip -l file.zip', '列出 ZIP 条目而不解压。', false], ['tar', 'tar -cvf file.tar dir/', '只打包，不进行压缩。', true],
    ['tar', 'tar -czvf file.tar.gz dir/', '打包并使用 gzip 压缩。', true], ['tar', 'tar -xzvf file.tar.gz', '解压 tar.gz 到当前目录。', true],
    ['tar', 'tar -xzvf file.tar.gz -C /path/to/dir', '解压到已存在的指定目录。', true], ['tar', 'tar -tzvf file.tar.gz', '查看 tar.gz 中的条目而不解包。', false],
    ['tar', 'tar -cjvf file.tar.bz2 dir/', '打包并使用 bzip2 压缩。', true], ['tar', 'tar -xjvf file.tar.bz2', '解压 tar.bz2。', true],
    ['tar', 'tar -cJvf file.tar.xz dir/', '打包并使用 xz 压缩。', true], ['tar', 'tar -xJvf file.tar.xz', '解压 tar.xz。', true],
    ['gzip', 'gzip file', '压缩单个文件；默认删除原文件并生成 .gz。', true], ['gzip', 'gzip -d file.gz', '解压 gzip 文件；默认移除压缩包。', true],
    ['gunzip', 'gunzip file.gz', 'gzip -d 的常见写法；还原压缩文件。', true], ['gzip', 'gzip -k file', '压缩并保留原文件。', true],
    ['gzip', 'gzip -dk file.gz', '解压并保留 .gz 压缩包。', true]
  ];
  archiveExamples.forEach(([name, cmd, description, changes]) => add('磁盘与归档', name, name === 'tar' ? 'tar [选项] <归档> <路径>' : `${name} [选项] <文件>`, description, [cmd], '压缩 解压 归档 zip tar gzip', changes, ...runoob(name)));

  const tutorialExtra = [
    ['compgen -c', 'compgen -c', '列出当前 Bash shell 能识别的命令名称。', 'Shell 命令列表 builtin', false, 'https://www.gnu.org/software/bash/manual/bash.html', 'GNU Bash 手册 ↗'],
    ['mount /sdb2 /mnt/xxx', 'mount <设备或分区> <挂载点>', '把已确认的分区挂载到指定目录。取证镜像应先评估只读挂载选项。', 'mount 分区 磁盘 取证', true, ...runoob('mount')],
    ['ip a', 'ip addr', '查看网卡和 IP 地址。', '网卡 IP 地址', false, 'https://man7.org/linux/man-pages/man8/ip-address.8.html', 'Linux 手册页 ↗'],
    ['cd', 'cd [目录]', '切换当前 shell 的工作目录；不带参数时回到主目录。', '目录 当前路径', true, ...runoob('cd')],
    ['mkdir', 'mkdir [-p] <目录>', '创建目录；-p 会一并创建不存在的父目录。', '创建文件夹 目录', true, ...runoob('mkdir')],
    ['vim 文件名', 'vim <文件>', '使用 Vim 编辑文本文件；退出前确认是否保存更改。', '文本编辑器 vi vim', true, 'https://www.runoob.com/linux/linux-vim.html', '菜鸟教程 ↗'],
    ['cat 文件名', 'cat <文件>', '输出文件内容；大文件使用 less 或 tail 更合适。', '查看文件内容 文本', false, ...runoob('cat')],
    ['ufw disable', 'ufw disable', '关闭 UFW 管理的防火墙规则。主机可能立即暴露到外部网络。', '防火墙 关闭 ufw', true, 'https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html', 'Ubuntu 手册页 ↗'],
    ['systemctl stop firewalld', 'systemctl stop firewalld', '立即停止 firewalld 服务；会改变防火墙运行状态。', '防火墙 firewalld 停止', true, 'https://www.freedesktop.org/software/systemd/man/latest/systemctl.html', 'systemd 官方手册 ↗'],
    ['ufw allow 8080/tcp', 'ufw allow <端口>/<协议>', '添加 UFW 放行规则；确认服务确实监听该端口，并检查云端安全组。', '防火墙 开端口 端口规则', true, 'https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html', 'Ubuntu 手册页 ↗'],
    ['dhclient -v', 'dhclient -v [网卡名]', '以详细模式申请 DHCP 地址租约；可能改变网卡地址和路由状态。', 'DHCP 获取地址 网络', true, 'https://man7.org/linux/man-pages/man8/dhclient.8.html', 'Linux 手册页 ↗'],
    ['ifconfig', 'ifconfig [网卡]', '查看传统网络接口信息；现代系统通常优先使用 ip addr。', '网卡 IP 网络接口', false, ...runoob('ifconfig')],
    ['ss -tuln', 'ss -tuln', '列出 TCP/UDP 监听端口，以数字形式显示地址和端口。', '端口占用 查端口 TCP UDP', false, ...runoob('ss')],
    ['ss -tulnp', 'ss -tulnp', '查看 TCP/UDP 监听端口及关联进程；显示进程通常需要管理员权限。', '端口占用 进程监听', false, ...runoob('ss')],
    ['netstat -tuln', 'netstat -tuln', '传统 net-tools 写法：查看 TCP/UDP 监听端口。', '端口占用 老命令 net-tools', false, ...runoob('netstat')],
    ['netstat -tulnp', 'netstat -tulnp', '传统 net-tools 写法：查看监听端口及关联进程。', '端口占用 进程监听', false, ...runoob('netstat')],
    ['history', 'history [数量]', '查看当前 shell 可用的历史命令；历史内容可能不完整。', '历史命令 取证 操作记录', false, ...runoob('history')],
    ['sudo apt update', 'sudo apt update', '更新 APT 软件包索引，不等同于升级已安装软件。', 'Ubuntu Debian apt 软件包', true, ...runoob('apt')],
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
    /^(sudo -i|sudo command|sudo -u |sudo -iu |su |whoami)/.test(cmd) ? '用户与权限' : /^(mount|fdisk|df|du)/.test(cmd) ? '磁盘与归档' : /^(ufw|systemctl stop firewalld|ifup|dhclient|ifconfig|ss |netstat|ip )/.test(cmd) ? '网络与端口' : /^(docker|docker-compose)/.test(cmd) ? '容器与 Docker' : /^(bt|1pctl|clpctl)/.test(cmd) ? '网站控制面板' : /^onestack/.test(cmd) ? '云平台与基础设施' : '命令与帮助',
    cmd, syntax, description, examples || [cmd], keywords, changes, source, sourceLabel
  ));
  add('网络与端口', 'firewalld', 'firewalld / firewall-cmd', 'firewalld 是常见 Linux 防火墙服务；用 firewall-cmd 查看、增删区域规则。', ['sudo firewall-cmd --list-all'], '防火墙 firewalld firewall-cmd', false, 'https://firewalld.org/documentation/', 'firewalld 官方文档 ↗');

  window.LINUX_COMMANDS = (window.LINUX_COMMANDS || []).concat(entries);
})();
