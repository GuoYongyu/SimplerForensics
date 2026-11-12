/*
 * APK 静态检查：签名结构读取（JAR 签名 v1、APK Signature Scheme v2/v3/v3.1）
 * 只读取证书与算法标识，不校验密码学签名有效性。
 */
(() => {
  'use strict';

  const root = typeof globalThis !== 'undefined' ? globalThis : window;
  const Api = root.ApkInspect = root.ApkInspect || {};
  const U = Api.util;
  const x509 = () => root.SimpleX509;

  const SCHEME_IDS = {
    0x7109871a: 'v2',
    0xf05368c0: 'v3',
    0x1b93ad61: 'v3.1',
    0x6dff800d: 'sourceStamp',
    0x42726577: 'verityPadding'
  };
  const ATTR_NAMES = {
    0x3ba06f8c: '签名轮换证明（proof-of-rotation）',
    0xbeeff00d: '防剥离保护（stripping protection）',
    0x559f8b02: '轮换最小 SDK（rotation-min-sdk-version）'
  };
  const SIG_ALGORITHMS = {
    0x0101: 'RSA-PSS-SHA256',
    0x0102: 'RSA-PSS-SHA512',
    0x0103: 'RSA-PKCS1-SHA256',
    0x0104: 'RSA-PKCS1-SHA512',
    0x0201: 'ECDSA-SHA256',
    0x0202: 'ECDSA-SHA512',
    0x0301: 'DSA-SHA256',
    0x0421: 'verity-RSA-SHA256',
    0x0423: 'verity-ECDSA-SHA256',
    0x0425: 'verity-DSA-SHA256'
  };
  const ALGORITHM_NAME = id => SIG_ALGORITHMS[id] || ('未知算法 0x' + id.toString(16));

  function readLengthPrefixed(bytes, offset) {
    if (offset + 4 > bytes.length) throw new Error('签名块长度字段缺失。');
    const length = U.readU32(bytes, offset);
    if (offset + 4 + length > bytes.length) throw new Error('签名块字段超出数据范围。');
    return { data: bytes.subarray(offset + 4, offset + 4 + length), next: offset + 4 + length };
  }
  function readSequence(bytes) {
    const items = [];
    let offset = 0;
    while (offset < bytes.length) {
      const item = readLengthPrefixed(bytes, offset);
      items.push(item.data);
      offset = item.next;
      if (items.length > 4096) throw new Error('签名块序列条目过多。');
    }
    return items;
  }

  async function certificateSummary(der, scheme) {
    const module = x509();
    if (!module) throw new Error('X.509 解析模块未加载。');
    const parsed = await module.parseCertificate(der);
    const sha256 = Api.hash.hex('sha256', der).match(/.{2}/g).join(':');
    const sha1 = Api.hash.hex('sha1', der).match(/.{2}/g).join(':');
    const md5 = Api.hash.hex('md5', der).match(/.{2}/g).join(':');
    const spki = parsed.subjectPublicKeyInfo;
    const publicKeySha256 = spki ? Api.hash.hex('sha256', spki).match(/.{2}/g).join(':') : null;
    const publicKeySha1 = spki ? Api.hash.hex('sha1', spki).match(/.{2}/g).join(':') : null;
    const subject = module.nameText(parsed.subject);
    const issuer = module.nameText(parsed.issuer);
    const debugPattern = /CN=Android Debug|O=Android Debug|Android Debug/i;
    return {
      scheme,
      subject,
      issuer,
      serial: parsed.serial,
      version: parsed.version,
      signatureAlgorithm: module.oidText(parsed.signatureAlgorithm.oid),
      publicKey: parsed.publicKey.algorithm + (parsed.publicKey.size ? ' · ' + parsed.publicKey.size : ''),
      notBefore: parsed.notBefore.iso,
      notBeforeRaw: parsed.notBefore.raw,
      notAfter: parsed.notAfter.iso,
      notAfterRaw: parsed.notAfter.raw,
      validityState: parsed.validityState,
      keyUsage: parsed.keyUsage,
      ca: parsed.ca,
      selfSigned: subject === issuer,
      debugLike: debugPattern.test(subject) || debugPattern.test(issuer),
      fingerprintSha256: sha256,
      fingerprintSha1: sha1,
      fingerprintMd5: md5,
      publicKeySha256,
      publicKeySha1,
      derLength: der.length,
      derBase64: base64(der)
    };
  }
  function base64(bytes) {
    if (typeof btoa === 'function') {
      let binary = '';
      const chunk = 0x8000;
      for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
      return btoa(binary);
    }
    return Buffer.from(bytes).toString('base64');
  }

  /* ------------------------------------------------------------------ */
  /* APK Signing Block                                                    */
  /* ------------------------------------------------------------------ */

  const APK_SIG_MAGIC = [0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32];

  async function readSigningBlock(source, cdOffset) {
    if (cdOffset < 32) return { present: false };
    const tail = await U.readRange(source, cdOffset - 24, 24);
    for (let i = 0; i < 16; i++) if (tail[8 + i] !== APK_SIG_MAGIC[i]) return { present: false };
    const size = U.readU64(tail, 0);
    if (size < 24 || size + 8 > cdOffset || size > 64 * 1024 * 1024) throw new Error('APK Signing Block 长度异常：' + size);
    const blockStart = cdOffset - size - 8;
    const block = await U.readRange(source, blockStart, size + 8);
    // 布局：[size(8)][pairs][size(8)][magic(16)]，总长度 size + 8。
    if (U.readU64(block, 0) !== size || U.readU64(block, size - 16) !== size) throw new Error('APK Signing Block 头尾长度不一致。');
    const pairs = [];
    let offset = 8;
    while (offset + 8 <= size - 16) {
      const pairLength = U.readU64(block, offset);
      if (pairLength < 4 || offset + 8 + pairLength > size - 8) throw new Error('APK Signing Block 条目长度异常。');
      const id = U.readU32(block, offset + 8);
      const value = block.subarray(offset + 12, offset + 8 + pairLength);
      pairs.push({ id, scheme: SCHEME_IDS[id] || null, size: pairLength - 4, value });
      offset += 8 + pairLength;
      if (pairs.length > 64) break;
    }
    return { present: true, size, blockStart, pairs };
  }

  function parseSignerV2(signerBytes) {
    const parts = readSequence(signerBytes);
    if (parts.length < 3) throw new Error('v2 签名者结构不完整（字段数 ' + parts.length + '，长度 ' + signerBytes.length + '）。');
    return parseSignedData(parts[0], parts[1], null, null);
  }
  function parseSignerV3(signerBytes) {
    // v3 signer: signed data, minSdk, maxSdk, signatures, public key
    let offset = 0;
    const signedData = readLengthPrefixed(signerBytes, offset);
    offset = signedData.next;
    if (offset + 8 > signerBytes.length) throw new Error('v3 签名者 SDK 字段缺失。');
    const minSdk = U.readU32(signerBytes, offset);
    const maxSdk = U.readU32(signerBytes, offset + 4);
    offset += 8;
    const signatures = readLengthPrefixed(signerBytes, offset);
    offset = signatures.next;
    const publicKey = readLengthPrefixed(signerBytes, offset);
    return { ...parseSignedData(signedData.data, signatures.data, minSdk, maxSdk), publicKeyLength: publicKey.data.length };
  }
  function parseSignedData(signedDataBytes, signaturesBytes, minSdk, maxSdk, warnings) {
    const notes = warnings || [];
    let offset = 0;
    const digestsField = readLengthPrefixed(signedDataBytes, offset);
    offset = digestsField.next;
    const certificatesField = readLengthPrefixed(signedDataBytes, offset);
    offset = certificatesField.next;
    let attributesField = null;
    if (offset + 4 <= signedDataBytes.length) {
      try {
        attributesField = readLengthPrefixed(signedDataBytes, offset);
        offset = attributesField.next;
      } catch (error) {
        notes.push('签名附加属性长度异常，已跳过：' + error.message);
      }
    }

    const digests = [];
    try {
      const digestPayload = readLengthPrefixed(digestsField.data, 0).data;
      let digestOffset = 0;
      while (digestOffset + 8 <= digestPayload.length) {
        const algorithm = U.readU32(digestPayload, digestOffset);
        const value = readLengthPrefixed(digestPayload, digestOffset + 4);
        digests.push({ algorithm: ALGORITHM_NAME(algorithm), algorithmId: algorithm, digestHex: U.hex(value.data).slice(0, 64) });
        digestOffset = value.next;
      }
    } catch (error) {
      notes.push('签名摘要列表解析不完整：' + error.message);
    }

    const certificates = readSequence(certificatesField.data);

    const attributes = [];
    if (attributesField) {
      let attrOffset = 0;
      while (attrOffset + 8 <= attributesField.data.length) {
        const length = U.readU32(attributesField.data, attrOffset);
        const end = attrOffset + 4 + length;
        if (length < 4 || end > attributesField.data.length) break;
        const id = U.readU32(attributesField.data, attrOffset + 4);
        const value = attributesField.data.subarray(attrOffset + 8, end);
        const view = { id, name: ATTR_NAMES[id] || ('未知属性 0x' + id.toString(16)), valueHex: U.hex(value).slice(0, 128) };
        if (id === 0xbeeff00d && value.length % 4 === 0) {
          view.schemes = Array.from({ length: value.length / 4 }, (_, index) => U.readU32(value, index * 4));
        }
        attributes.push(view);
        attrOffset = end;
      }
    }

    const signatures = [];
    if (signaturesBytes) {
      try {
        const signaturePayload = readLengthPrefixed(signaturesBytes, 0).data;
        let sigOffset = 0;
        while (sigOffset + 4 <= signaturePayload.length) {
          const algorithm = U.readU32(signaturePayload, sigOffset);
          const signature = readLengthPrefixed(signaturePayload, sigOffset + 4);
          signatures.push({ algorithm: ALGORITHM_NAME(algorithm), algorithmId: algorithm, length: signature.data.length });
          sigOffset = signature.next;
        }
      } catch (error) {
        notes.push('签名列表解析不完整：' + error.message);
      }
    }
    return { digests, certificates, attributes, signatures, minSdk, maxSdk };
  }

  function parseSignatureScheme(value, kind) {
    if (kind !== 'v2') return null;
    try {
      // 块值先包裹一层"签名者序列"长度前缀。
      const sequence = readLengthPrefixed(value, 0);
      return readSequence(sequence.data).map(parseSignerV2);
    } catch (error) {
      return { error: error.message };
    }
  }

  function parseV3Block(value) {
    // 结构：长度前缀的签名者序列 + minSdk(u32) + maxSdk(u32)
    const result = { signers: [], minSdk: null, maxSdk: null, warnings: [] };
    try {
      const sequence = readLengthPrefixed(value, 0);
      result.signers = readSequence(sequence.data).map(parseSignerV3);
      if (value.length - sequence.next >= 8) {
        result.minSdk = U.readU32(value, sequence.next);
        result.maxSdk = U.readU32(value, sequence.next + 4);
      }
    } catch (error) {
      result.warnings.push('v3 签名块解析不完整：' + error.message);
    }
    return result;
  }

  /* ------------------------------------------------------------------ */
  /* JAR 签名（v1）                                                       */
  /* ------------------------------------------------------------------ */

  const MANIFEST_HEADERS = ['Manifest-Version', 'Created-By', 'Built-By', 'Signature-Version', 'X-Android-APK-Signed'];

  function parseManifestText(text) {
    const result = { headers: {}, entries: 0 };
    let currentSection = 0;
    for (const line of text.split(/\r?\n/)) {
      if (!line) { currentSection++; continue; }
      if (line.startsWith(' ') || line.startsWith('\t')) continue;
      const index = line.indexOf(':');
      if (index <= 0) continue;
      const name = line.slice(0, index).trim();
      const value = line.slice(index + 1).trim();
      if (name === 'Name') result.entries++;
      if (!currentSection && MANIFEST_HEADERS.includes(name)) result.headers[name] = value;
      for (const header of MANIFEST_HEADERS) {
        if (name === header && !result.headers[name]) result.headers[name] = value;
      }
    }
    return result;
  }

  function parsePkcs7(bytes) {
    const module = x509();
    const certificate = module.parseSingle(bytes, 'PKCS#7 数据');
    if (certificate.tag !== 0x30) throw new Error('PKCS#7 顶层不是 SEQUENCE。');
    const parts = module.children(certificate);
    if (parts.length < 2) throw new Error('PKCS#7 结构不完整。');
    const contentType = module.decodeOid(module.content(parts[0]));
    if (contentType !== '1.2.840.113549.1.7.2') throw new Error('PKCS#7 内容类型不是 SignedData（' + contentType + '）。');
    const wrapper = parts[1];
    if (wrapper.tag !== 0xa0) throw new Error('PKCS#7 SignedData 包装缺失。');
    const signedData = module.readTlv(wrapper.bytes, wrapper.contentStart);
    const fields = module.children(signedData);
    const result = { certificates: [], digestAlgorithms: [], signerInfos: [] };
    const digestSet = fields.find(field => field.tag === 0x31);
    if (digestSet) {
      for (const algorithm of module.children(digestSet)) {
        try { result.digestAlgorithms.push(module.oidText(module.decodeOid(module.content(module.children(algorithm)[0])))); } catch { /* 忽略单个算法 */ }
      }
    }
    const certWrapper = fields.find(field => field.tag === 0xa0);
    if (certWrapper) {
      for (const item of module.children(certWrapper)) {
        if (item.tag !== 0x30) continue;
        result.certificates.push(item.bytes.subarray(item.start, item.end));
      }
    }
    const signerSet = fields[fields.length - 1];
    if (signerSet && signerSet.tag === 0x31) {
      for (const signer of module.children(signerSet)) {
        const info = {};
        const items = module.children(signer);
        // SignerInfo：version、sid、digestAlgorithm、[0] signedAttrs、signatureAlgorithm、signature
        for (let i = 2; i < items.length; i++) {
          const item = items[i];
          if (item.tag !== 0x30) continue;
          const inner = module.children(item);
          if (!inner.length || inner[0].tag !== 0x06) continue;
          const oid = module.decodeOid(module.content(inner[0]));
          const name = module.OID_NAMES[oid] || oid;
          if (!info.digestAlgorithm) { info.digestAlgorithm = oid; info.digestAlgorithmName = name; }
          else if (!info.signatureAlgorithm) { info.signatureAlgorithm = oid; info.signatureAlgorithmName = name; }
        }
        result.signerInfos.push(info);
      }
    }
    return result;
  }

  async function analyzeJarSignature(source, entries, warnings) {
    const metaEntries = entries.filter(entry => entry.name.startsWith('META-INF/') && !entry.name.endsWith('/'));
    const signatureFiles = metaEntries.filter(entry => /\.(RSA|DSA|EC)$/i.test(entry.name));
    const sfFiles = metaEntries.filter(entry => /\.SF$/i.test(entry.name));
    const manifestFile = metaEntries.find(entry => entry.name.toUpperCase() === 'META-INF/MANIFEST.MF');
    if (!signatureFiles.length && !sfFiles.length && !manifestFile) return { present: false };
    const result = {
      present: signatureFiles.length > 0,
      manifest: null,
      signatureFiles: [],
      warnings: []
    };
    if (manifestFile) {
      try {
        const bytes = await Api.zip.readEntry(source, manifestFile, { maxSize: 32 * 1024 * 1024 });
        const text = U.utf8(bytes);
        result.manifest = {
          path: manifestFile.name,
          size: manifestFile.size,
          sha256: Api.hash.hex('sha256', bytes),
          ...parseManifestText(text)
        };
      } catch (error) {
        result.warnings.push('无法读取 META-INF/MANIFEST.MF：' + error.message);
      }
    }
    for (const entry of signatureFiles) {
      const file = { path: entry.name, size: entry.size, blockType: entry.name.split('.').pop().toUpperCase(), certificates: [], digestAlgorithms: [], signerInfos: [], sha256: '' };
      try {
        const bytes = await Api.zip.readEntry(source, entry, { maxSize: 32 * 1024 * 1024 });
        file.sha256 = Api.hash.hex('sha256', bytes);
        const container = parsePkcs7(bytes);
        file.digestAlgorithms = container.digestAlgorithms;
        file.signerInfos = container.signerInfos;
        for (const der of container.certificates) {
          try {
            file.certificates.push(await certificateSummary(der, 'v1'));
          } catch (error) {
            result.warnings.push('证书解析失败（' + entry.name + '）：' + error.message);
          }
        }
      } catch (error) {
        result.warnings.push('无法解析 ' + entry.name + '：' + error.message);
      }
      result.signatureFiles.push(file);
    }
    for (const sf of sfFiles) {
      try {
        const bytes = await Api.zip.readEntry(source, sf, { maxSize: 8 * 1024 * 1024 });
        const text = U.utf8(bytes);
        const parsed = parseManifestText(text);
        result.signatureFiles.push({
          path: sf.name,
          size: sf.size,
          blockType: 'SF',
          sha256: Api.hash.hex('sha256', bytes),
          sfHeaders: parsed.headers
        });
      } catch (error) {
        result.warnings.push('无法读取 ' + sf.name + '：' + error.message);
      }
    }
    return result;
  }

  /* ------------------------------------------------------------------ */
  /* 汇总                                                                 */
  /* ------------------------------------------------------------------ */

  function dedupeCertificates(certificates) {
    const byFingerprint = new Map();
    for (const cert of certificates) {
      if (!cert) continue;
      const existing = byFingerprint.get(cert.fingerprintSha256);
      if (existing) {
        if (!existing.schemes.includes(cert.scheme)) existing.schemes.push(cert.scheme);
        continue;
      }
      byFingerprint.set(cert.fingerprintSha256, { ...cert, schemes: [cert.scheme] });
    }
    return [...byFingerprint.values()];
  }

  async function analyzeSignature(source, directory) {
    const warnings = [];
    const signature = {
      apkSigningBlock: { present: false },
      schemes: {
        v1: { present: false },
        v2: { present: false, signers: [] },
        v3: { present: false, signers: [] },
        v3_1: { present: false, signers: [] },
        sourceStamp: { present: false }
      },
      certificates: [],
      debugCertificate: false,
      warnings
    };
    try {
      const v1 = await analyzeJarSignature(source, directory.entries, warnings);
      signature.schemes.v1 = v1;
      if (v1.warnings?.length) warnings.push(...v1.warnings);
      signature.certificates.push(...(v1.signatureFiles || []).flatMap(file => file.certificates || []));
    } catch (error) {
      warnings.push('JAR 签名（v1）解析失败：' + error.message);
    }

    try {
      const block = await readSigningBlock(source, directory.cdOffset);
      signature.apkSigningBlock = {
        present: block.present,
        size: block.size || 0,
        pairs: (block.pairs || []).map(pair => ({ id: pair.id, idHex: '0x' + pair.id.toString(16), scheme: pair.scheme, size: pair.size }))
      };
      if (block.present) {
        for (const pair of block.pairs) {
          if (pair.scheme === 'v2') {
            const signers = parseSignatureScheme(pair.value, 'v2');
            if (signers.error) { warnings.push('v2 签名块解析失败：' + signers.error); continue; }
            signature.schemes.v2 = { present: true, signers: [] };
            for (const signer of signers) {
              const certificates = [];
              for (const der of signer.certificates) {
                try { certificates.push(await certificateSummary(der, 'v2')); }
                catch (error) { warnings.push('v2 证书解析失败：' + error.message); }
              }
              signature.schemes.v2.signers.push({
                digestAlgorithms: signer.digests.map(item => item.algorithm),
                signatureAlgorithms: signer.signatures.map(item => item.algorithm),
                attributes: signer.attributes,
                certificates
              });
              signature.certificates.push(...certificates);
            }
          } else if (pair.scheme === 'v3' || pair.scheme === 'v3.1') {
            const parsed = parseV3Block(pair.value);
            warnings.push(...parsed.warnings);
            const target = pair.scheme === 'v3' ? signature.schemes.v3 : signature.schemes.v3_1;
            target.present = true;
            target.minSdk = parsed.minSdk;
            target.maxSdk = parsed.maxSdk;
            target.signers = [];
            for (const signer of parsed.signers) {
              const certificates = [];
              for (const der of signer.certificates) {
                try { certificates.push(await certificateSummary(der, pair.scheme)); }
                catch (error) { warnings.push(pair.scheme + ' 证书解析失败：' + error.message); }
              }
              target.signers.push({
                minSdk: signer.minSdk,
                maxSdk: signer.maxSdk,
                digestAlgorithms: signer.digests.map(item => item.algorithm),
                signatureAlgorithms: signer.signatures.map(item => item.algorithm),
                attributes: signer.attributes,
                certificates
              });
              signature.certificates.push(...certificates);
            }
          } else if (pair.scheme === 'sourceStamp') {
            signature.schemes.sourceStamp = { present: true, size: pair.size };
          }
        }
      }
    } catch (error) {
      warnings.push('APK Signing Block 解析失败：' + error.message);
    }

    signature.certificates = dedupeCertificates(signature.certificates);
    signature.debugCertificate = signature.certificates.some(cert => cert.debugLike);
    signature.anyScheme = Boolean(signature.schemes.v1.present || signature.schemes.v2.present || signature.schemes.v3.present || signature.schemes.v3_1.present);
    if (!signature.anyScheme) warnings.push('没有发现 v1/v2/v3 签名结构；APK 可能未签名，或使用了不受支持的自定义签名方案。');
    if (signature.schemes.v2.present && signature.schemes.v3.present) {
      const v2Certs = signature.schemes.v2.signers.flatMap(signer => signer.certificates.map(cert => cert.fingerprintSha256));
      const v3Certs = signature.schemes.v3.signers.flatMap(signer => signer.certificates.map(cert => cert.fingerprintSha256));
      const differs = v2Certs.some(fingerprint => !v3Certs.includes(fingerprint)) || v3Certs.some(fingerprint => !v2Certs.includes(fingerprint));
      signature.schemeMismatch = differs;
      if (differs) warnings.push('v2 与 v3 签名证书指纹不一致；可能是签名轮换，也可能表示签名结构被修改，需要进一步核对。');
    }
    if (signature.schemes.v1.present && (signature.schemes.v2.present || signature.schemes.v3.present)) {
      const v1Certs = signature.schemes.v1.signatureFiles.flatMap(file => (file.certificates || []).map(cert => cert.fingerprintSha256));
      const modern = new Set([
        ...signature.schemes.v2.signers.flatMap(signer => signer.certificates.map(cert => cert.fingerprintSha256)),
        ...signature.schemes.v3.signers.flatMap(signer => signer.certificates.map(cert => cert.fingerprintSha256))
      ]);
      if (v1Certs.length && modern.size && v1Certs.some(fingerprint => !modern.has(fingerprint))) {
        warnings.push('v1 签名证书与 v2/v3 签名证书不一致；可能是轮换签名，也可能存在重新打包。');
      }
    }
    return signature;
  }

  Object.assign(Api, {
    signature: {
      analyzeSignature,
      readSigningBlock,
      parsePkcs7,
      parseManifestText,
      ALGORITHM_NAME
    }
  });
  if (typeof module === 'object' && module.exports) module.exports = Api;
})();
