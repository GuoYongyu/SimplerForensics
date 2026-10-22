(() => {
  'use strict';

  const input = document.querySelector('#certificate-input');
  const status = document.querySelector('#status');
  const results = document.querySelector('#certificate-results');
  const tabs = document.querySelector('#certificate-tabs');
  const detail = document.querySelector('#certificate-detail');
  let certificates = [];
  let activeIndex = 0;

  const OID_NAMES = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
    '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber',
    '2.5.4.9': 'street', '2.5.4.12': 'title', '1.2.840.113549.1.9.1': 'emailAddress',
    '1.2.840.113549.1.1.1': 'RSA', '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption', '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256', '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512', '1.2.840.10045.2.1': 'id-ecPublicKey',
    '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
    '2.16.840.1.101.3.4.3.2': 'dsa-with-SHA256', '1.2.840.10040.4.1': 'DSA',
    '2.5.29.19': 'Basic Constraints', '2.5.29.15': 'Key Usage', '2.5.29.37': 'Extended Key Usage',
    '2.5.29.17': 'Subject Alternative Name', '2.5.29.14': 'Subject Key Identifier',
    '2.5.29.35': 'Authority Key Identifier', '2.5.29.31': 'CRL Distribution Points',
    '1.3.6.1.5.5.7.1.1': 'Authority Information Access', '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
    '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication', '1.3.6.1.5.5.7.3.3': 'Code Signing',
    '1.3.6.1.5.5.7.3.4': 'Email Protection', '1.3.6.1.5.5.7.3.8': 'Time Stamping',
    '1.3.6.1.5.5.7.3.9': 'OCSP Signing', '1.3.6.1.5.5.7.48.1': 'OCSP',
    '1.3.6.1.5.5.7.48.2': 'CA Issuers', '1.2.840.10045.3.1.7': 'secp256r1 / prime256v1',
    '1.3.132.0.34': 'secp384r1', '1.3.132.0.35': 'secp521r1', '1.3.101.110': 'X25519',
    '1.3.101.111': 'X448', '1.2.840.113549.1.1.8': 'MGF1', '1.2.840.113549.1.9.16.2.47': 'Signing Certificate V2'
  };
  const EXT_LABELS = {
    '2.5.29.19': '基本约束', '2.5.29.15': '密钥用途', '2.5.29.37': '扩展密钥用途',
    '2.5.29.17': '主题备用名称', '2.5.29.14': '主题密钥标识符', '2.5.29.35': '颁发者密钥标识符',
    '2.5.29.31': 'CRL 分发点', '1.3.6.1.5.5.7.1.1': '颁发机构信息访问',
    '2.5.29.32': '证书策略', '2.5.29.30': '名称约束', '2.5.29.36': '策略约束',
    '2.5.29.54': '禁止策略映射'
  };
  const KU_NAMES = ['数字签名', '不可否认/内容承诺', '密钥加密', '数据加密', '密钥协商', '证书签名', 'CRL 签名', '仅 encipherOnly', '仅 decipherOnly'];

  function fail(message) { throw new Error(message); }
  function readTlv(bytes, offset) {
    if (offset >= bytes.length) fail('DER 数据意外结束。');
    const start = offset;
    const tag = bytes[offset++];
    if (offset >= bytes.length) fail('DER 长度字段缺失。');
    let length = bytes[offset++];
    if (length & 0x80) {
      const count = length & 0x7f;
      if (!count) fail('不支持 BER 不定长编码；请提供 DER 编码证书。');
      if (count > 4 || offset + count > bytes.length) fail('DER 长度字段无效。');
      length = 0;
      for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
      if (length < 128) fail('DER 长度编码不是最短形式。');
    }
    const contentStart = offset;
    const end = contentStart + length;
    if (!Number.isSafeInteger(end) || end > bytes.length) fail('DER 字段长度超出证书数据范围，证书可能已截断。');
    return { tag, start, contentStart, end, length, bytes };
  }
  function children(node) {
    const items = [];
    let offset = node.contentStart;
    while (offset < node.end) {
      const item = readTlv(node.bytes, offset);
      items.push(item);
      offset = item.end;
    }
    if (offset !== node.end) fail('DER 子字段边界无效。');
    return items;
  }
  function content(node) { return node.bytes.subarray(node.contentStart, node.end); }
  function parseSingle(bytes, label) {
    const node = readTlv(bytes, 0);
    if (node.end !== bytes.length) fail(label + '包含 DER 结构之后的额外数据。');
    return node;
  }
  function decodeOid(bytes) {
    if (!bytes.length) fail('OID 字段为空。');
    const values = [];
    let value = 0n;
    let inValue = false;
    for (const byte of bytes) {
      value = (value << 7n) | BigInt(byte & 0x7f);
      inValue = true;
      if (!(byte & 0x80)) {
        values.push(value);
        value = 0n;
        inValue = false;
      }
    }
    if (inValue) fail('OID 字段末尾不完整。');
    const first = values.shift();
    const firstArc = first < 40n ? 0n : first < 80n ? 1n : 2n;
    const arcs = [firstArc.toString(), (first - firstArc * 40n).toString(), ...values.map(String)];
    return arcs.join('.');
  }
  function hex(bytes) { return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('').toUpperCase(); }
  function oidText(oid) { return (OID_NAMES[oid] ? OID_NAMES[oid] + ' · ' : '') + oid; }
  function decodeString(node) {
    const bytes = content(node);
    if (node.tag === 0x1e) {
      if (bytes.length % 2) return 'BMPString 字节长度无效：' + hex(bytes);
      let result = '';
      for (let i = 0; i < bytes.length; i += 2) result += String.fromCharCode(bytes[i] * 256 + bytes[i + 1]);
      return result;
    }
    if (node.tag === 0x1c) {
      if (bytes.length % 4) return 'UniversalString 字节长度无效：' + hex(bytes);
      let result = '';
      for (let i = 0; i < bytes.length; i += 4) result += String.fromCodePoint(bytes[i] * 0x1000000 + bytes[i + 1] * 0x10000 + bytes[i + 2] * 0x100 + bytes[i + 3]);
      return result;
    }
    try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch { return '无法按 UTF-8 解码：' + hex(bytes); }
  }
  function parseName(node) {
    const attributes = [];
    for (const set of children(node)) {
      if (set.tag !== 0x31) continue;
      for (const sequence of children(set)) {
        const pair = children(sequence);
        if (pair.length < 2 || pair[0].tag !== 0x06) continue;
        const oid = decodeOid(content(pair[0]));
        attributes.push({ oid, name: OID_NAMES[oid] || oid, value: decodeString(pair[1]) });
      }
    }
    return attributes;
  }
  function nameText(attributes) {
    return attributes.length ? attributes.map(item => item.name + '=' + item.value.replace(/([,+=\\<>#;])/g, '\\$1')).join(', ') : '（空名称）';
  }
  function parseAlgorithm(node) {
    const parts = children(node);
    if (!parts.length || parts[0].tag !== 0x06) fail('算法标识符缺少 OID。');
    const oid = decodeOid(content(parts[0]));
    return { oid, name: OID_NAMES[oid] || '未知算法', parameters: parts[1] || null };
  }
  function unsignedBigInt(bytes) { return bytes.length ? BigInt('0x' + hex(bytes)) : 0n; }
  function parseInteger(node) {
    if (node.tag !== 0x02 || !node.length) fail('预期为 DER INTEGER。');
    return { raw: hex(content(node)), value: unsignedBigInt(content(node)) };
  }
  function bitLength(bytes) {
    let i = 0;
    while (i < bytes.length && bytes[i] === 0) i++;
    if (i === bytes.length) return 0;
    let lead = bytes[i], bits = 0;
    while (lead) { bits++; lead >>= 1; }
    return (bytes.length - i - 1) * 8 + bits;
  }
  function parsePublicKey(node) {
    const parts = children(node);
    if (parts.length < 2 || parts[1].tag !== 0x03) fail('SubjectPublicKeyInfo 结构不完整。');
    const algorithm = parseAlgorithm(parts[0]);
    const bitString = content(parts[1]);
    if (!bitString.length || bitString[0] !== 0) fail('公钥 BIT STRING 不是完整字节。');
    const keyBytes = bitString.subarray(1);
    const info = { algorithm: algorithm.name, oid: algorithm.oid, parameters: '', size: '', exponent: '' };
    if (algorithm.oid === '1.2.840.113549.1.1.1') {
      const rsa = children(parseSingle(keyBytes, 'RSA 公钥'));
      if (rsa.length >= 2) {
        const modulus = content(rsa[0]);
        const exponent = content(rsa[1]);
        info.size = bitLength(modulus) + ' bit';
        info.exponent = unsignedBigInt(exponent).toString();
      }
    } else if (algorithm.oid === '1.2.840.10045.2.1') {
      const curve = algorithm.parameters && algorithm.parameters.tag === 0x06 ? decodeOid(content(algorithm.parameters)) : '';
      info.parameters = curve ? (OID_NAMES[curve] || curve) : '未编码曲线参数';
      info.size = Math.max(0, (keyBytes.length - 1) * 4) + ' bit 坐标（估算）';
    } else if (algorithm.oid === '1.3.101.112') info.size = '256 bit';
    else if (algorithm.oid === '1.3.101.113') info.size = '448 bit';
    else if (algorithm.oid === '1.2.840.10040.4.1') {
      info.parameters = algorithm.parameters ? '含 DSA 参数' : '参数缺失';
      const dsaPublicValue = parseSingle(keyBytes, 'DSA 公钥');
      if (dsaPublicValue.tag === 0x02) info.size = bitLength(content(dsaPublicValue)) + ' bit';
    } else if (algorithm.parameters && algorithm.parameters.tag === 0x06) info.parameters = oidText(decodeOid(content(algorithm.parameters)));
    return info;
  }
  function parseTime(node) {
    const raw = decodeString(node);
    const match = node.tag === 0x17
      ? raw.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$/)
      : node.tag === 0x18 ? raw.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?(Z|[+-]\d{4})$/) : null;
    if (!match) return { raw, iso: '无法识别时间格式', timestamp: NaN };
    let year, month, day, hour, minute, second, fraction, zone;
    if (node.tag === 0x17) {
      year = Number(match[1]); year += year >= 50 ? 1900 : 2000;
      month = match[2]; day = match[3]; hour = match[4]; minute = match[5]; second = match[6] || '00'; fraction = '';
      zone = match[7];
    } else {
      year = Number(match[1]); month = match[2]; day = match[3]; hour = match[4]; minute = match[5]; second = match[6]; fraction = match[7] || ''; zone = match[8];
    }
    const millis = Number(('0.' + fraction) || 0) * 1000;
    let timestamp = Date.UTC(year, Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second), Math.floor(millis));
    if (zone !== 'Z') {
      const offset = (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3, 5))) * 60000;
      timestamp += zone[0] === '+' ? -offset : offset;
    }
    const date = new Date(timestamp);
    return { raw, iso: Number.isNaN(date.getTime()) ? '无法识别时间值' : date.toISOString(), timestamp };
  }
  function extensionInner(ext) { return parseSingle(ext.value, EXT_LABELS[ext.oid] || '扩展值'); }
  function parseBasicConstraints(node) {
    const parts = children(node);
    const caNode = parts.find(item => item.tag === 0x01);
    const path = parts.find(item => item.tag === 0x02);
    return { ca: caNode ? content(caNode).some(Boolean) : false, pathLength: path ? unsignedBigInt(content(path)).toString() : '' };
  }
  function parseKeyUsage(node) {
    if (node.tag !== 0x03) fail('Key Usage 扩展不是 BIT STRING。');
    const bits = content(node);
    const names = [];
    if (!bits.length || bits[0] > 7) return names;
    for (let bit = 0; bit < Math.min((bits.length - 1) * 8 - bits[0], KU_NAMES.length); bit++) {
      if (bits[1 + Math.floor(bit / 8)] & (0x80 >> (bit % 8))) names.push(KU_NAMES[bit]);
    }
    return names;
  }
  function parseSubjectAltName(node) {
    return children(node).map(item => {
      const bytes = content(item);
      if (item.tag === 0x82) return 'DNS: ' + decodeString({ ...item, tag: 0x16 });
      if (item.tag === 0x81) return '邮箱: ' + decodeString({ ...item, tag: 0x16 });
      if (item.tag === 0x86) return 'URI: ' + decodeString({ ...item, tag: 0x16 });
      if (item.tag === 0x87) {
        if (bytes.length === 4) return 'IP: ' + Array.from(bytes).join('.');
        if (bytes.length === 16) return 'IP: ' + Array.from({ length: 8 }, (_, i) => ((bytes[i * 2] << 8) | bytes[i * 2 + 1]).toString(16)).join(':');
        return 'IP: ' + hex(bytes);
      }
      if (item.tag === 0x88) return 'Registered ID: ' + decodeOid(bytes);
      if (item.tag === 0xa4) return '目录名称: ' + nameText(parseName(readTlv(item.bytes, item.contentStart)));
      return '上下文标签 ' + item.tag.toString(16).toUpperCase() + ': ' + hex(bytes);
    });
  }
  function parseAuthorityKeyIdentifier(node) {
    const parts = children(node);
    const key = parts.find(item => item.tag === 0x80);
    const serial = parts.find(item => item.tag === 0x82);
    return { keyIdentifier: key ? hex(content(key)) : '', serial: serial ? hex(content(serial)) : '' };
  }
  function parseAia(node) {
    return children(node).map(item => {
      const parts = children(item);
      if (parts.length < 2) return hex(content(item));
      const method = decodeOid(content(parts[0]));
      const location = parts[1];
      let value;
      if (location.tag === 0x86 || location.tag === 0x81) value = decodeString({ ...location, tag: 0x16 });
      else value = '上下文标签 ' + location.tag.toString(16).toUpperCase() + '，' + location.length + ' 字节';
      return (OID_NAMES[method] || method) + ': ' + value;
    });
  }
  function collectUris(node, out) {
    if (node.tag === 0x86) out.push(decodeString({ ...node, tag: 0x16 }));
    else if ((node.tag & 0x20) || node.tag === 0xa0 || node.tag === 0xa1 || node.tag === 0xa2) {
      let items;
      try { items = children(node); } catch { return; }
      for (const item of items) collectUris(item, out);
    }
  }
  function parseExtensions(tbs) {
    const wrapper = tbs.find(item => item.tag === 0xa3);
    if (!wrapper) return [];
    const sequence = readTlv(wrapper.bytes, wrapper.contentStart);
    return children(sequence).map(item => {
      const parts = children(item);
      const oid = decodeOid(content(parts[0]));
      const critical = parts[1] && parts[1].tag === 0x01 ? content(parts[1]).some(Boolean) : false;
      const octets = parts.find(part => part.tag === 0x04);
      if (!octets) fail('扩展 ' + oid + ' 缺少 OCTET STRING 数据。');
      const ext = { oid, critical, value: content(octets), label: EXT_LABELS[oid] || '未知扩展' };
      const inner = extensionInner(ext);
      if (oid === '2.5.29.19') ext.parsed = parseBasicConstraints(inner);
      else if (oid === '2.5.29.15') ext.parsed = parseKeyUsage(inner);
      else if (oid === '2.5.29.37') ext.parsed = children(inner).map(value => decodeOid(content(value)));
      else if (oid === '2.5.29.17') ext.parsed = parseSubjectAltName(inner);
      else if (oid === '2.5.29.14') ext.parsed = hex(content(inner));
      else if (oid === '2.5.29.35') ext.parsed = parseAuthorityKeyIdentifier(inner);
      else if (oid === '1.3.6.1.5.5.7.1.1') ext.parsed = parseAia(inner);
      else if (oid === '2.5.29.31') {
        const uris = [];
        collectUris(inner, uris);
        ext.parsed = uris.length ? uris : ['含 CRL 分发点，结构字段未提取到 URI'];
      } else ext.rawHex = hex(ext.value);
      return ext;
    });
  }
  async function fingerprint(bytes) {
    if (typeof crypto === 'undefined' || !crypto.subtle) return '当前浏览器环境不支持 Web Crypto 指纹计算';
    try { return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))).match(/.{2}/g).join(':'); }
    catch { return 'Web Crypto 未能计算 SHA-256 指纹'; }
  }
  async function parseCertificate(bytes) {
    const certificate = parseSingle(bytes, '证书');
    if (certificate.tag !== 0x30) fail('证书顶层不是 ASN.1 SEQUENCE。输入可能不是 X.509 DER 证书。');
    const certParts = children(certificate);
    if (certParts.length < 3) fail('X.509 证书结构不完整。');
    const tbs = children(certParts[0]);
    let i = 0, versionNumber = 0;
    if (tbs[i] && tbs[i].tag === 0xa0) {
      const wrappedVersion = readTlv(tbs[i].bytes, tbs[i].contentStart);
      versionNumber = Number(unsignedBigInt(content(wrappedVersion)));
      i++;
    }
    if (tbs.length < i + 6) fail('TBSCertificate 缺少必需字段。');
    const serial = parseInteger(tbs[i++]);
    const tbsSignature = parseAlgorithm(tbs[i++]);
    const issuer = parseName(tbs[i++]);
    const validity = children(tbs[i++]);
    if (validity.length < 2) fail('证书有效期结构不完整。');
    const notBefore = parseTime(validity[0]);
    const notAfter = parseTime(validity[1]);
    const subject = parseName(tbs[i++]);
    const publicKey = parsePublicKey(tbs[i++]);
    const signatureAlgorithm = parseAlgorithm(certParts[1]);
    const extensions = parseExtensions(tbs);
    const basic = extensions.find(ext => ext.oid === '2.5.29.19');
    const usage = extensions.find(ext => ext.oid === '2.5.29.15');
    let validityState;
    const now = Date.now();
    if (Number.isNaN(notBefore.timestamp) || Number.isNaN(notAfter.timestamp)) validityState = '时间格式无法识别';
    else if (now < notBefore.timestamp) validityState = '尚未生效';
    else if (now > notAfter.timestamp) validityState = '已过期';
    else validityState = '在有效期内';
    const subjectKey = extensions.find(ext => ext.oid === '2.5.29.14');
    const authorityKey = extensions.find(ext => ext.oid === '2.5.29.35');
    return {
      subject, issuer, serial: serial.raw.replace(/^00(?=[0-9A-F]{2})/, ''), version: 'X.509 v' + (versionNumber + 1),
      notBefore, notAfter, validityState, publicKey, signatureAlgorithm, tbsSignature,
      ca: basic ? basic.parsed.ca : null, pathLength: basic ? basic.parsed.pathLength : '',
      keyUsage: usage ? usage.parsed : [], extensions,
      subjectKeyId: subjectKey ? subjectKey.parsed : '',
      authorityKeyId: authorityKey ? authorityKey.parsed.keyIdentifier : '',
      fingerprint: await fingerprint(bytes), byteLength: bytes.length,
      signatureMatch: signatureAlgorithm.oid === tbsSignature.oid
    };
  }
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
