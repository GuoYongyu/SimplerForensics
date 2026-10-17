(() => {
  const items = [
    ['首页', '../index.html'], ['Base64', '../base64/index.html'], ['时间戳', '../timestamp/index.html'],
    ['MD5', '../md5/index.html'], ['文件格式', '../signatures/index.html'], ['图片尺寸', '../image-fix/index.html'], ['伪装分析', '../file-disguise/index.html'], ['APK 解析', '../apk/index.html'], ['二维码识别', '../qr-reader/index.html'], ['Linux 指令', '../linux/index.html'], ['市场监管检索', '../market-search/index.html'], ['Windows 配置', '../windows/index.html']
  ];
  const current = location.pathname.split('/').filter(Boolean).slice(-2, -1)[0] || '';
  const bar = document.createElement('nav'); bar.className = 'tool-nav'; bar.setAttribute('aria-label','工具导航');
  bar.innerHTML = items.map(([label,href]) => `<a href="${href}" ${href.includes(current) && current ? 'aria-current="page"' : ''}>${label}</a>`).join('');
  const target = document.querySelector('.breadcrumbs'); if (target) target.after(bar);
})();
