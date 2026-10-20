(() => {
  const groups = [
    ['文件分析', [['格式速查', '../signatures/index.html'], ['十六进制', '../hex-viewer/index.html'], ['元数据', '../metadata-viewer/index.html'], ['伪装分析', '../file-disguise/index.html'], ['图片尺寸', '../image-fix/index.html'], ['EXE 分析', '../exe-analysis/index.html']]],
    ['移动与媒体', [['APK 解析', '../apk/index.html'], ['二维码', '../qr-reader/index.html']]],
    ['数据处理', [['Base64', '../base64/index.html'], ['时间戳', '../timestamp/index.html'], ['MD5', '../md5/index.html']]],
    ['资料检索', [['Linux', '../linux/index.html'], ['代码指令', '../code-commands/index.html'], ['市场监管', '../market-search/index.html'], ['Windows', '../windows/index.html']]]
  ];
  const current = location.pathname.split('/').filter(Boolean).slice(-2, -1)[0] || '';
  const bar = document.createElement('nav'); bar.className = 'tool-nav'; bar.setAttribute('aria-label','工具导航');
  bar.innerHTML = `<a class="tool-nav-home" href="../index.html">工具首页</a>${groups.map(([group,items]) => `<div class="tool-nav-group"><span>${group}</span><div>${items.map(([label,href]) => `<a href="${href}" ${href.includes(current) && current ? 'aria-current="page"' : ''}>${label}</a>`).join('')}</div></div>`).join('')}`;
  document.querySelectorAll('.status').forEach(status => {
    if (!status.hasAttribute('role')) status.setAttribute('role', 'status');
    if (!status.hasAttribute('aria-live')) status.setAttribute('aria-live', 'polite');
  });
  const target = document.querySelector('.breadcrumbs'); if (target) target.after(bar);
})();
