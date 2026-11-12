(() => {
  'use strict';

  const input = document.querySelector('#certificate-input');
  const status = document.querySelector('#status');
  const results = document.querySelector('#certificate-results');
  const tabs = document.querySelector('#certificate-tabs');
  const detail = document.querySelector('#certificate-detail');
  let certificates = [];
  let activeIndex = 0;

  // DER / X.509 读取逻辑位于 assets/x509.js，与 APK 签名检查共用。
  const { fail, parseCertificate, nameText, oidText } = window.SimpleX509;
  function decodeBase64(value) {
    const clean = value.replace(/\s+/g, '');
    if (!clean) fail('没有找到证书 Base64 内容。');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) fail('输入含有非 Base64 字符；请粘贴 PEM 或标准 Base64 DER 内容。');
    const body = clean.replace(/=+$/, '');
    if (body.length % 4 === 1 || (clean.includes('=') && clean.length % 4 !== 0)) fail('Base64 长度或填充无效。');
    const padded = body.padEnd(Math.ceil(body.length / 4) * 4, '=');
    let raw;
    try { raw = atob(padded); } catch { fail('Base64 解码失败。'); }
    return Uint8Array.from(raw, char => char.charCodeAt(0));
  }
  function extractCertificates(text) {
    const pemPattern = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
    const matches = Array.from(text.matchAll(pemPattern));
    if (matches.length) {
      if (text.replace(pemPattern, '').trim()) fail('PEM 证书块之间或外部包含未识别内容；请只粘贴 CERTIFICATE 块。');
      return matches.map(match => decodeBase64(match[1]));
    }
    if (/-----BEGIN|-----END/.test(text)) fail('PEM 标记不完整，或输入的不是 CERTIFICATE 块。');
    return [decodeBase64(text)];
  }
  function escapeHtml(value) {
    return String(value == null || value === '' ? '—' : value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  }
  function makeRows(rows) {
    return rows.map(([label, value, mono]) => '<div class="ca-row"><dt>' + escapeHtml(label) + '</dt><dd' + (mono ? ' class="mono"' : '') + '>' + escapeHtml(value) + '</dd></div>').join('');
  }
  function extensionValue(ext) {
    if (ext.oid === '2.5.29.19') {
      const data = ['CA: ' + (ext.parsed.ca ? 'TRUE' : 'FALSE')];
      if (ext.parsed.pathLength !== '') data.push('pathLenConstraint: ' + ext.parsed.pathLength);
      return data.join('；');
    }
    if (ext.oid === '2.5.29.35') return [ext.parsed.keyIdentifier ? 'keyIdentifier: ' + ext.parsed.keyIdentifier : '', ext.parsed.serial ? 'serialNumber: ' + ext.parsed.serial : ''].filter(Boolean).join('\n') || '无可显示字段';
    if (Array.isArray(ext.parsed)) return ext.parsed.map(value => ext.oid === '2.5.29.37' ? oidText(value) : value).join('\n') || '无可显示值';
    if (typeof ext.parsed === 'string') return ext.parsed;
    return '原始扩展值（' + ext.value.length + ' 字节）：' + (ext.rawHex.length > 640 ? ext.rawHex.slice(0, 640) + '…（已截断显示）' : ext.rawHex);
  }
  function render() {
    const cert = certificates[activeIndex];
    tabs.innerHTML = certificates.map((item, index) => '<button type="button" class="ca-tab' + (index === activeIndex ? ' is-active' : '') + '" role="tab" aria-selected="' + (index === activeIndex) + '" aria-controls="certificate-detail" data-index="' + index + '">证书 ' + (index + 1) + (item.subject.length ? ' · ' + escapeHtml(item.subject.find(attr => attr.oid === '2.5.4.3')?.value || item.subject[0].value) : '') + '</button>').join('');
    const caLabel = cert.ca === true ? '声明为 CA' : cert.ca === false ? 'Basic Constraints 声明为非 CA' : '未声明 Basic Constraints';
    const keySign = cert.keyUsage.includes('证书签名');
    const summaryRows = [
      ['主题', nameText(cert.subject)], ['颁发者', nameText(cert.issuer)], ['序列号', cert.serial, true], ['版本', cert.version],
      ['签名算法', oidText(cert.signatureAlgorithm.oid)], ['公钥算法', cert.publicKey.algorithm + (cert.publicKey.size ? ' · ' + cert.publicKey.size : '')],
      ['公钥参数', cert.publicKey.parameters || '—'], ['公钥指数', cert.publicKey.exponent || '—'],
      ['有效期起始（UTC）', cert.notBefore.iso + ' · 原始值 ' + cert.notBefore.raw], ['有效期截止（UTC）', cert.notAfter.iso + ' · 原始值 ' + cert.notAfter.raw],
      ['SHA-256 指纹', cert.fingerprint, true], ['DER 长度', cert.byteLength + ' 字节']
    ];
    const keyRows = [
      ['Basic Constraints', cert.ca === null ? '扩展不存在' : caLabel + (cert.pathLength ? '；pathLenConstraint=' + cert.pathLength : '')],
      ['Key Usage', cert.keyUsage.length ? cert.keyUsage.join('、') : '扩展不存在或未声明用途'],
      ['Subject Key Identifier', cert.subjectKeyId || '未提供', true], ['Authority Key Identifier', cert.authorityKeyId || '未提供', true],
      ['签名算法一致性', cert.signatureMatch ? 'TBSCertificate 与外层签名算法 OID 一致' : '两个签名算法 OID 不一致']
    ];
    const extensionCards = cert.extensions.map(ext => '<article class="ca-extension"><header><strong>' + escapeHtml(ext.label) + '</strong><span class="chip">' + (ext.critical ? 'Critical' : 'Non-critical') + '</span><span class="ca-oid mono">' + escapeHtml(ext.oid) + '</span></header><pre>' + escapeHtml(extensionValue(ext)) + '</pre></article>').join('');
    detail.innerHTML = '<section class="panel"><div class="ca-summary"><div><span class="subtle">证书判读</span><strong>' + escapeHtml(cert.ca === true ? 'CA 证书' : cert.ca === false ? '非 CA 证书' : 'CA 属性未声明') + '</strong></div><div><span class="subtle">本机时间比较</span><strong>' + escapeHtml(cert.validityState) + '</strong></div><div><span class="subtle">证书签名用途</span><strong>' + escapeHtml(keySign ? 'Key Usage 含证书签名' : 'Key Usage 未声明证书签名') + '</strong></div></div><p class="hint">CA 判读取自证书内 Basic Constraints；Key Usage 单独列出。这里不验证签名、信任链、主机名或吊销状态。</p><div class="ca-field-grid">' + makeRows(summaryRows) + '</div></section>' +
      '<section class="panel"><h2>CA 与密钥标识</h2><dl class="ca-field-grid">' + makeRows(keyRows) + '</dl></section>' +
      '<section class="panel"><div class="ca-section-heading"><h2>证书扩展（' + cert.extensions.length + '）</h2></div>' + (extensionCards || '<div class="status warning">证书未包含扩展字段。</div>') + '</section>';
    tabs.querySelectorAll('[data-index]').forEach(button => button.addEventListener('click', () => {
      activeIndex = Number(button.dataset.index);
      render();
    }));
    results.hidden = false;
  }
  function showStatus(message, kind) {
    status.className = 'status' + (kind ? ' ' + kind : '');
    status.textContent = message;
  }
  document.querySelector('#parse').addEventListener('click', async () => {
    results.hidden = true;
    certificates = [];
    tabs.replaceChildren();
    detail.replaceChildren();
    try {
      if (input.value.length > 5 * 1024 * 1024) fail('输入超过 5 MiB 上限；请分批粘贴证书。');
      const blocks = extractCertificates(input.value);
      if (blocks.length > 20) fail('一次最多解析 20 张证书。');
      showStatus('正在解析 ' + blocks.length + ' 张证书…', '');
      const parsed = [];
      for (const bytes of blocks) parsed.push(await parseCertificate(bytes));
      certificates = parsed;
      activeIndex = 0;
      render();
      showStatus('解析完成：' + certificates.length + ' 张 X.509 证书。所有字段均在本机浏览器内读取。', 'success');
    } catch (error) {
      showStatus('解析失败：' + (error.message || '输入格式无效。'), 'error');
    }
  });
  document.querySelector('#clear').addEventListener('click', () => {
    input.value = '';
    certificates = [];
    activeIndex = 0;
    tabs.replaceChildren();
    detail.replaceChildren();
    results.hidden = true;
    showStatus('已清空证书内容和解析结果。', '');
  });
})();
