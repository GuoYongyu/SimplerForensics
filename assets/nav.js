(() => {
  const groups = [
    ['文件分析', [
      ['格式速查', 'signature.svg', '../signatures/index.html'],
      ['十六进制', 'hex-viewer.svg', '../hex-viewer/index.html'],
      ['元数据', 'metadata-viewer.svg', '../metadata-viewer/index.html'],
      ['伪装分析', 'file-disguise.svg', '../file-disguise/index.html'],
      ['图片尺寸', 'image-fix.svg', '../image-fix/index.html'],
      ['EXE 分析', 'exe-analysis.svg', '../exe-analysis/index.html'],
      ['CA 证书', 'ca-certificate.svg', '../ca-certificate/index.html'],
    ]],
    ['移动与媒体', [
      ['APK 解析', 'apk-file.svg', '../apk/index.html'],
      ['二维码', 'qr.svg', '../qr-reader/index.html'],
    ]],
    ['数据处理', [
      ['手机号归属地', 'phone-lookup.svg', '../phone-lookup/index.html'],
      ['Base64', 'base64.svg', '../base64/index.html'],
      ['时间戳', 'timestamp.svg', '../timestamp/index.html'],
      ['密文字典匹配', 'md5.svg', '../ciphertext/index.html'],
    ]],
    ['资料检索', [
      ['Linux', 'linux-terminal.svg', '../linux/index.html'],
      ['代码指令', 'code-commands.svg', '../code-commands/index.html'],
      ['Windows', 'windows.svg', '../windows/index.html'],
    ]],
  ];
  const current = location.pathname.split('/').filter(Boolean).slice(-2, -1)[0] || '';
  const bar = document.createElement('nav');
  bar.className = 'tool-nav';
  bar.setAttribute('aria-label', '工具导航');
  const icon = (name) => `<img class="tool-nav-icon" src="../assets/icons/${name}" alt="" aria-hidden="true">`;
  bar.innerHTML = `<a class="tool-nav-home" href="../index.html"><svg class="tool-nav-home-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m3.5 10 8.5-7 8.5 7v10a1 1 0 0 1-1 1h-5.5v-6h-4v6H4.5a1 1 0 0 1-1-1z"/></svg><span>工具首页</span></a>${groups.map(([group, items]) => `<div class="tool-nav-group"><span>${group}</span><div>${items.map(([label, image, href]) => `<a class="tool-nav-link" href="${href}" ${href.includes(current) && current ? 'aria-current="page"' : ''}>${icon(image)}<span>${label}</span></a>`).join('')}</div></div>`).join('')}`;
  document.querySelectorAll('.status').forEach(status => {
    if (!status.hasAttribute('role')) status.setAttribute('role', 'status');
    if (!status.hasAttribute('aria-live')) status.setAttribute('aria-live', 'polite');
  });
  const target = document.querySelector('.breadcrumbs');
  if (target) target.after(bar);
})();
