/*
 * SimplerForensics · HashCat workbench core
 *
 * Pure, DOM-free helpers shared by the page and the Node regression tests:
 * hash functions, mask compiler/enumerator, a deliberately small regex
 * generator, word-mutation rules, constraints and hashcat command builders.
 *
 * The browser page loads this file as a classic script and uses
 * window.HashcatCore. The worker only receives the hash functions through
 * Function#toString, so this file must not depend on globals.
 */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.HashcatCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var LOWER = 'abcdefghijklmnopqrstuvwxyz';
  var UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  var DIGITS = '0123456789';
  var SYMBOLS = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';
  var HEX_LOWER = '0123456789abcdef';
  var HEX_UPPER = '0123456789ABCDEF';
  var PRINTABLE = (function () {
    var out = '';
    for (var i = 32; i <= 126; i++) out += String.fromCharCode(i);
    return out;
  })();
  var ALL = LOWER + UPPER + DIGITS + SYMBOLS;
  var COUNT_CAP = 1e12;

  var MODES = {
    MD5: { key: 'MD5', label: 'MD5', hashcat: 0, hexLength: 32, group: 'unsalted', kind: 'unsalted', algorithm: 'MD5' },
    SHA1: { key: 'SHA1', label: 'SHA-1', hashcat: 100, hexLength: 40, group: 'unsalted', kind: 'unsalted', algorithm: 'SHA1' },
    SHA256: { key: 'SHA256', label: 'SHA-256', hashcat: 1400, hexLength: 64, group: 'unsalted', kind: 'unsalted', algorithm: 'SHA256' },
    SHA512: { key: 'SHA512', label: 'SHA-512', hashcat: 1700, hexLength: 128, group: 'unsalted', kind: 'unsalted', algorithm: 'SHA512' },
    NTLM: { key: 'NTLM', label: 'NTLM', hashcat: 1000, hexLength: 32, group: 'unsalted', kind: 'unsalted', algorithm: 'NTLM' },
    BCRYPT: { key: 'BCRYPT', label: 'bcrypt', hashcat: 3200, group: 'unsalted', kind: 'bcrypt' },
    MD5_SALT_AFTER: { key: 'MD5_SALT_AFTER', label: 'MD5($pass.$salt)', hashcat: 10, hexLength: 32, group: 'salted', kind: 'salted', algorithm: 'MD5', saltPosition: 'after' },
    MD5_SALT_BEFORE: { key: 'MD5_SALT_BEFORE', label: 'MD5($salt.$pass)', hashcat: 20, hexLength: 32, group: 'salted', kind: 'salted', algorithm: 'MD5', saltPosition: 'before' },
    SHA1_SALT_AFTER: { key: 'SHA1_SALT_AFTER', label: 'SHA-1($pass.$salt)', hashcat: 110, hexLength: 40, group: 'salted', kind: 'salted', algorithm: 'SHA1', saltPosition: 'after' },
    SHA1_SALT_BEFORE: { key: 'SHA1_SALT_BEFORE', label: 'SHA-1($salt.$pass)', hashcat: 120, hexLength: 40, group: 'salted', kind: 'salted', algorithm: 'SHA1', saltPosition: 'before' },
    SHA256_SALT_AFTER: { key: 'SHA256_SALT_AFTER', label: 'SHA-256($pass.$salt)', hashcat: 1410, hexLength: 64, group: 'salted', kind: 'salted', algorithm: 'SHA256', saltPosition: 'after' },
    SHA256_SALT_BEFORE: { key: 'SHA256_SALT_BEFORE', label: 'SHA-256($salt.$pass)', hashcat: 1420, hexLength: 64, group: 'salted', kind: 'salted', algorithm: 'SHA256', saltPosition: 'before' },
    SHA512_SALT_AFTER: { key: 'SHA512_SALT_AFTER', label: 'SHA-512($pass.$salt)', hashcat: 1710, hexLength: 128, group: 'salted', kind: 'salted', algorithm: 'SHA512', saltPosition: 'after' },
    SHA512_SALT_BEFORE: { key: 'SHA512_SALT_BEFORE', label: 'SHA-512($salt.$pass)', hashcat: 1720, hexLength: 128, group: 'salted', kind: 'salted', algorithm: 'SHA512', saltPosition: 'before' },
    NETNTLMv2: { key: 'NETNTLMv2', label: 'NetNTLMv2', hashcat: 5600, group: 'windows', kind: 'netntlmv2' },
    DCC2: { key: 'DCC2', label: 'MS-Cache v2 (DCC2)', hashcat: 2100, group: 'windows', kind: 'dcc2' }
  };

  var HEX_LENGTH_MODE = { 32: 'MD5', 40: 'SHA1', 64: 'SHA256', 128: 'SHA512' };
  var BCRYPT_RE = /^\$2[aby]\$(?:0[4-9]|[12]\d|3[01])\$[./A-Za-z0-9]{53}$/;

  var MASK_TOKENS = {
    l: LOWER, u: UPPER, d: DIGITS, s: SYMBOLS, a: ALL,
    h: HEX_LOWER, H: HEX_UPPER
  };
  var BLOCK_TOKENS = {
    lower: 'l', upper: 'u', digits: 'd', symbols: 's', all: 'a',
    hexLower: 'h', hexUpper: 'H'
  };
  var BLOCK_LABELS = {
    literal: '字面文本',
    lower: '小写字母', upper: '大写字母', digits: '数字', symbols: '符号',
    all: '全部字符', hexLower: '十六进制（小写）', hexUpper: '十六进制（大写）',
    custom1: '自定义字符集 1', custom2: '自定义字符集 2',
    custom3: '自定义字符集 3', custom4: '自定义字符集 4'
  };

  function uniqueChars(value) {
    return Array.from(new Set(Array.from(String(value)))).join('');
  }

  function complementChars(value) {
    var set = new Set(Array.from(String(value)));
    return Array.from(PRINTABLE).filter(function (ch) { return !set.has(ch); }).join('');
  }

  function clampInt(value, min, max, fallback) {
    var n = Number(value);
    if (!Number.isFinite(n)) n = fallback;
    n = Math.trunc(n);
    return Math.min(max, Math.max(min, n));
  }

  function commaNumber(text) {
    return String(text).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  function formatCount(value) {
    var n;
    try { n = typeof value === 'bigint' ? value : BigInt(Math.trunc(Number(value))); }
    catch (_) { n = 0n; }
    var exact = commaNumber(n.toString());
    if (n < 10000n) return exact;
    var number = Number(n);
    function trim(v) { return String(v).replace(/\.0+$/, '').replace(/(\.\d*?)0+$/, '$1'); }
    if (n < 100000000n) {
      var wan = number / 10000;
      return exact + '（约 ' + (wan >= 1000 ? Math.round(wan).toLocaleString('en-US') : trim(wan.toFixed(2))) + ' 万）';
    }
    if (n < 1000000000000n) return exact + '（约 ' + trim((number / 100000000).toFixed(2)) + ' 亿）';
    if (n < 10000000000000000n) return exact + '（约 ' + trim((number / 1000000000000).toFixed(2)) + ' 万亿）';
    var exponent = Math.floor(Math.log10(number));
    return exact + '（约 ' + (number / Math.pow(10, exponent)).toFixed(2) + ' × 10^' + exponent + '）';
  }

  function formatDuration(ms) {
    if (!Number.isFinite(ms) || ms < 0) return '—';
    var seconds = ms / 1000;
    if (seconds < 1) return (seconds * 1000).toFixed(0) + ' 毫秒';
    if (seconds < 60) return seconds.toFixed(2) + ' 秒';
    if (seconds < 3600) return Math.floor(seconds / 60) + ' 分 ' + (seconds % 60).toFixed(1) + ' 秒';
    return Math.floor(seconds / 3600) + ' 小时 ' + Math.floor((seconds % 3600) / 60) + ' 分';
  }

  /* ------------------------------------------------------------------ *
   * Hash functions
   * ------------------------------------------------------------------ */

  function hexOf(buffer) {
    var bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
    return out;
  }

  function md5(bytes) {
    var len = bytes.length;
    var buf = new Uint8Array((((len + 8) >>> 6) + 1) * 64);
    buf.set(bytes);
    buf[len] = 128;
    var bit = len * 8;
    for (var bi = 0; bi < 8; bi++) buf[buf.length - 8 + bi] = Math.floor(bit / Math.pow(2, 8 * bi)) & 255;
    var a0 = 0x67452301 | 0, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476 | 0;
    var shifts = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    if (!md5._k) {
      var kk = new Int32Array(64);
      for (var ki = 0; ki < 64; ki++) kk[ki] = Math.floor(Math.abs(Math.sin(ki + 1)) * 4294967296) | 0;
      md5._k = kk;
    }
    var k = md5._k;
    var m = new Int32Array(16);
    for (var off = 0; off < buf.length; off += 64) {
      for (var mi = 0; mi < 16; mi++) {
        var p = off + mi * 4;
        m[mi] = buf[p] | buf[p + 1] << 8 | buf[p + 2] << 16 | buf[p + 3] << 24;
      }
      var a = a0, b = b0, c = c0, d = d0;
      for (var i = 0; i < 64; i++) {
        var f, g, shift;
        if (i < 16) { f = (b & c) | (~b & d); g = i; shift = shifts[i % 4]; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; shift = shifts[4 + i % 4]; }
        else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; shift = shifts[8 + i % 4]; }
        else { f = c ^ (b | ~d); g = (7 * i) % 16; shift = shifts[12 + i % 4]; }
        var x = (a + f + k[i] + m[g]) | 0;
        a = d; d = c; c = b;
        b = (b + ((x << shift) | (x >>> (32 - shift)))) | 0;
      }
      a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
    }
    var words = [a0, b0, c0, d0];
    var out = '';
    for (var wi = 0; wi < 4; wi++) {
      var n = words[wi];
      out += [n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255]
        .map(function (v) { return v.toString(16).padStart(2, '0'); }).join('');
    }
    return out;
  }

  function md4(bytes) {
    var len = bytes.length;
    var buf = new Uint8Array((((len + 8) >>> 6) + 1) * 64);
    buf.set(bytes);
    buf[len] = 0x80;
    var bit = len * 8;
    for (var bi = 0; bi < 8; bi++) buf[buf.length - 8 + bi] = Math.floor(bit / Math.pow(2, 8 * bi)) & 255;
    var a0 = 0x67452301 | 0, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476 | 0;
    function rotl(x, s) { return (x << s) | (x >>> (32 - s)); }
    function F(x, y, z) { return (x & y) | (~x & z); }
    function G(x, y, z) { return (x & y) | (x & z) | (y & z); }
    function H(x, y, z) { return x ^ y ^ z; }
    var X = new Int32Array(16);
    for (var off = 0; off < buf.length; off += 64) {
      for (var xi = 0; xi < 16; xi++) {
        var xp = off + xi * 4;
        X[xi] = buf[xp] | buf[xp + 1] << 8 | buf[xp + 2] << 16 | buf[xp + 3] << 24;
      }
      var a = a0, b = b0, c = c0, d = d0;

      // Round 1
      a = rotl((a + F(b, c, d) + X[0]) | 0, 3);
      d = rotl((d + F(a, b, c) + X[1]) | 0, 7);
      c = rotl((c + F(d, a, b) + X[2]) | 0, 11);
      b = rotl((b + F(c, d, a) + X[3]) | 0, 19);
      a = rotl((a + F(b, c, d) + X[4]) | 0, 3);
      d = rotl((d + F(a, b, c) + X[5]) | 0, 7);
      c = rotl((c + F(d, a, b) + X[6]) | 0, 11);
      b = rotl((b + F(c, d, a) + X[7]) | 0, 19);
      a = rotl((a + F(b, c, d) + X[8]) | 0, 3);
      d = rotl((d + F(a, b, c) + X[9]) | 0, 7);
      c = rotl((c + F(d, a, b) + X[10]) | 0, 11);
      b = rotl((b + F(c, d, a) + X[11]) | 0, 19);
      a = rotl((a + F(b, c, d) + X[12]) | 0, 3);
      d = rotl((d + F(a, b, c) + X[13]) | 0, 7);
      c = rotl((c + F(d, a, b) + X[14]) | 0, 11);
      b = rotl((b + F(c, d, a) + X[15]) | 0, 19);

      // Round 2
      a = rotl((a + G(b, c, d) + X[0] + 0x5a827999) | 0, 3);
      d = rotl((d + G(a, b, c) + X[4] + 0x5a827999) | 0, 5);
      c = rotl((c + G(d, a, b) + X[8] + 0x5a827999) | 0, 9);
      b = rotl((b + G(c, d, a) + X[12] + 0x5a827999) | 0, 13);
      a = rotl((a + G(b, c, d) + X[1] + 0x5a827999) | 0, 3);
      d = rotl((d + G(a, b, c) + X[5] + 0x5a827999) | 0, 5);
      c = rotl((c + G(d, a, b) + X[9] + 0x5a827999) | 0, 9);
      b = rotl((b + G(c, d, a) + X[13] + 0x5a827999) | 0, 13);
      a = rotl((a + G(b, c, d) + X[2] + 0x5a827999) | 0, 3);
      d = rotl((d + G(a, b, c) + X[6] + 0x5a827999) | 0, 5);
      c = rotl((c + G(d, a, b) + X[10] + 0x5a827999) | 0, 9);
      b = rotl((b + G(c, d, a) + X[14] + 0x5a827999) | 0, 13);
      a = rotl((a + G(b, c, d) + X[3] + 0x5a827999) | 0, 3);
      d = rotl((d + G(a, b, c) + X[7] + 0x5a827999) | 0, 5);
      c = rotl((c + G(d, a, b) + X[11] + 0x5a827999) | 0, 9);
      b = rotl((b + G(c, d, a) + X[15] + 0x5a827999) | 0, 13);

      // Round 3
      a = rotl((a + H(b, c, d) + X[0] + 0x6ed9eba1) | 0, 3);
      d = rotl((d + H(a, b, c) + X[8] + 0x6ed9eba1) | 0, 9);
      c = rotl((c + H(d, a, b) + X[4] + 0x6ed9eba1) | 0, 11);
      b = rotl((b + H(c, d, a) + X[12] + 0x6ed9eba1) | 0, 15);
      a = rotl((a + H(b, c, d) + X[2] + 0x6ed9eba1) | 0, 3);
      d = rotl((d + H(a, b, c) + X[10] + 0x6ed9eba1) | 0, 9);
      c = rotl((c + H(d, a, b) + X[6] + 0x6ed9eba1) | 0, 11);
      b = rotl((b + H(c, d, a) + X[14] + 0x6ed9eba1) | 0, 15);
      a = rotl((a + H(b, c, d) + X[1] + 0x6ed9eba1) | 0, 3);
      d = rotl((d + H(a, b, c) + X[9] + 0x6ed9eba1) | 0, 9);
      c = rotl((c + H(d, a, b) + X[5] + 0x6ed9eba1) | 0, 11);
      b = rotl((b + H(c, d, a) + X[13] + 0x6ed9eba1) | 0, 15);
      a = rotl((a + H(b, c, d) + X[3] + 0x6ed9eba1) | 0, 3);
      d = rotl((d + H(a, b, c) + X[11] + 0x6ed9eba1) | 0, 9);
      c = rotl((c + H(d, a, b) + X[7] + 0x6ed9eba1) | 0, 11);
      b = rotl((b + H(c, d, a) + X[15] + 0x6ed9eba1) | 0, 15);

      a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
    }
    var words = [a0, b0, c0, d0];
    var out = '';
    for (var wi = 0; wi < 4; wi++) {
      var n = words[wi];
      out += [n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255]
        .map(function (v) { return v.toString(16).padStart(2, '0'); }).join('');
    }
    return out;
  }

  function ntlm(text) {
    var value = String(text);
    var bytes = new Uint8Array(value.length * 2);
    for (var i = 0; i < value.length; i++) {
      var code = value.charCodeAt(i);
      bytes[i * 2] = code & 255;
      bytes[i * 2 + 1] = code >>> 8;
    }
    return md4(bytes);
  }

  function hexToBytes(hex) {
    var value = String(hex || '').trim();
    if (value.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(value)) throw new Error('无效的十六进制字节串');
    var out = new Uint8Array(value.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
    return out;
  }

  function utf16leBytes(text) {
    var value = String(text);
    var bytes = new Uint8Array(value.length * 2);
    for (var i = 0; i < value.length; i++) {
      var code = value.charCodeAt(i);
      bytes[i * 2] = code & 255;
      bytes[i * 2 + 1] = code >>> 8;
    }
    return bytes;
  }

  function concatBytes(left, right) {
    var out = new Uint8Array(left.length + right.length);
    out.set(left, 0);
    out.set(right, left.length);
    return out;
  }

  function hmacMd5(keyBytes, messageBytes) {
    var key = keyBytes instanceof Uint8Array ? keyBytes : new Uint8Array(keyBytes);
    var message = messageBytes instanceof Uint8Array ? messageBytes : new Uint8Array(messageBytes);
    var block = 64;
    if (key.length > block) key = hexToBytes(md5(key));
    var ipad = new Uint8Array(block);
    var opad = new Uint8Array(block);
    ipad.fill(0x36);
    opad.fill(0x5c);
    for (var i = 0; i < key.length; i++) {
      ipad[i] ^= key[i];
      opad[i] ^= key[i];
    }
    var inner = hexToBytes(md5(concatBytes(ipad, message)));
    return hexToBytes(md5(concatBytes(opad, inner)));
  }

  /* ------------------------------------------------------------------ *
   * Mask compiler
   * ------------------------------------------------------------------ */

  function expandCustomSet(value) {
    var chars = Array.from(String(value || ''));
    var out = [];
    for (var i = 0; i < chars.length; i++) {
      var ch = chars[i];
      if (ch !== '?') { out.push(ch); continue; }
      var next = chars[++i];
      if (next === undefined) return { ok: false, error: '自定义字符集以 ? 结尾，请用 ?? 表示字面问号' };
      if (next === '?') { out.push('?'); continue; }
      if (MASK_TOKENS[next]) { out.push.apply(out, Array.from(MASK_TOKENS[next])); continue; }
      if (/^[1-4]$/.test(next)) return { ok: false, error: '自定义字符集不能引用其他 ?1–?4 字符集' };
      return { ok: false, error: '自定义字符集中存在未知标记 ?' + next };
    }
    return { ok: true, chars: uniqueChars(out.join('')) };
  }

  function maskFromBlocks(blocks, customSets) {
    var out = '';
    (blocks || []).forEach(function (block) {
      block = block || {};
      if (block.type === 'literal') {
        out += String(block.text || '').replace(/\?/g, '??');
        return;
      }
      if (Object.prototype.hasOwnProperty.call(BLOCK_TOKENS, block.type)) {
        var count = clampInt(block.count, 1, 64, 1);
        out += ('?' + BLOCK_TOKENS[block.type]).repeat(count);
        return;
      }
      var custom = /^custom([1-4])$/.exec(block.type || '');
      if (custom) {
        var n = clampInt(block.count, 1, 64, 1);
        out += ('?' + custom[1]).repeat(n);
      }
    });
    return out;
  }

  function compileMask(mask, customSets) {
    customSets = customSets || [];
    var expanded = [0, 1, 2, 3].map(function (index) { return expandCustomSet(customSets[index] || ''); });
    var chars = Array.from(String(mask || ''));
    var positions = [];
    var customUsed = [];
    var normalized = '';
    for (var i = 0; i < chars.length; i++) {
      var ch = chars[i];
      if (ch !== '?') {
        if (ch === '\n' || ch === '\r') return { ok: false, error: '掩码中不能包含换行' };
        positions.push({ chars: [ch], kind: 'literal', token: ch });
        normalized += ch;
        continue;
      }
      var next = chars[++i];
      if (next === undefined) return { ok: false, error: '掩码以 ? 结尾；字面问号请写成 ??' };
      if (next === '?') {
        positions.push({ chars: ['?'], kind: 'literal', token: '??' });
        normalized += '??';
        continue;
      }
      if (MASK_TOKENS[next]) {
        positions.push({ chars: Array.from(MASK_TOKENS[next]), kind: next, token: '?' + next });
        normalized += '?' + next;
        continue;
      }
      if (/^[1-4]$/.test(next)) {
        var index = Number(next) - 1;
        if (!expanded[index].ok) return { ok: false, error: '自定义字符集 ' + next + '：' + expanded[index].error };
        if (!expanded[index].chars) return { ok: false, error: '自定义字符集 ' + next + ' 为空' };
        positions.push({ chars: Array.from(expanded[index].chars), kind: 'custom' + next, token: '?' + next });
        if (customUsed.indexOf(index) === -1) customUsed.push(index);
        normalized += '?' + next;
        continue;
      }
      if (next === 'b') return { ok: false, error: '不支持 ?b（原始字节）掩码；请改用 ?h 或自定义字符集' };
      return { ok: false, error: '未知掩码标记 ?' + next + '（位置 ' + (i + 1) + '）' };
    }
    if (!positions.length) return { ok: false, error: '掩码为空，请添加至少一个块' };
    if (positions.length > 64) return { ok: false, error: '掩码长度超过 64 个位置' };
    var keyspace = 1n;
    positions.forEach(function (position) { keyspace *= BigInt(position.chars.length); });
    return {
      ok: true,
      positions: positions,
      mask: normalized,
      length: positions.length,
      keyspace: keyspace,
      customUsed: customUsed
    };
  }

  function buildMaskBatch(compiled, startIndex, maxCount) {
    var positions = compiled.positions;
    var sizes = positions.map(function (position) { return position.chars.length; });
    var digits = new Array(positions.length);
    var rem = Math.max(0, Math.trunc(Number(startIndex) || 0));
    for (var i = positions.length - 1; i >= 0; i--) {
      digits[i] = rem % sizes[i];
      rem = Math.floor(rem / sizes[i]);
    }
    var out = [];
    for (var n = 0; n < maxCount; n++) {
      var value = '';
      for (var p = 0; p < positions.length; p++) value += positions[p].chars[digits[p]];
      out.push(value);
      var q = positions.length - 1;
      while (q >= 0) {
        digits[q]++;
        if (digits[q] < sizes[q]) break;
        digits[q] = 0;
        q--;
      }
      if (q < 0) break;
    }
    return out;
  }

  /* ------------------------------------------------------------------ *
   * Small regex generator
   * ------------------------------------------------------------------ */

  function parseRegex(pattern) {
    var source = String(pattern || '');
    var chars = Array.from(source);
    var i = 0;
    var warnings = [];
    var unbounded = false;

    function peek() { return chars[i]; }
    function nextChar() { return chars[i++]; }
    function fail(message, position) {
      var error = new Error(message + (position === undefined ? '' : '（位置 ' + (position + 1) + '）'));
      error.position = position;
      throw error;
    }

    function parseAlternation() {
      var items = [parseSequence()];
      while (peek() === '|') { nextChar(); items.push(parseSequence()); }
      return items.length === 1 ? items[0] : { type: 'alt', items: items };
    }

    function parseSequence() {
      var items = [];
      while (i < chars.length && peek() !== ')' && peek() !== '|') items.push(parseQuantified());
      return items.length === 1 ? items[0] : { type: 'seq', items: items };
    }

    function parseQuantified() {
      var atom = parseAtom();
      var ch = peek();
      var min, max;
      if (ch === '?') { nextChar(); min = 0; max = 1; }
      else if (ch === '*') { nextChar(); min = 0; max = Infinity; unbounded = true; }
      else if (ch === '+') { nextChar(); min = 1; max = Infinity; unbounded = true; }
      else if (ch === '{') {
        var start = i;
        nextChar();
        var first = '';
        while (/^\d$/.test(peek() || '')) first += nextChar();
        if (!first) fail('量词 { 后缺少数字', start);
        min = Number(first);
        if (peek() === '}') { nextChar(); max = min; }
        else if (peek() === ',') {
          nextChar();
          var second = '';
          while (/^\d$/.test(peek() || '')) second += nextChar();
          if (peek() !== '}') fail('量词格式错误，应为 {n}、{n,} 或 {n,m}', start);
          nextChar();
          max = second ? Number(second) : Infinity;
          if (max === Infinity) unbounded = true;
        } else fail('量词格式错误，应为 {n}、{n,} 或 {n,m}', start);
        if (min > 1000 || (Number.isFinite(max) && max > 1000)) fail('量词数值过大（上限 1000）', start);
        if (Number.isFinite(max) && max < min) fail('量词上限小于下限', start);
      } else return atom;

      if (peek() === '?' || peek() === '+') fail('不支持惰性量词或占有量词', i);
      if (peek() === '*' || peek() === '+' || peek() === '{') fail('重复的量词', i);
      return { type: 'repeat', node: atom, min: min, max: max };
    }

    function parseAtom() {
      var ch = nextChar();
      if (ch === '(') {
        if (peek() === '?') {
          var start = i;
          nextChar();
          if (peek() === ':') nextChar();
          else fail('不支持环视、命名分组或内联标志；可使用 (?:...) 分组', start);
        }
        var node = parseAlternation();
        if (nextChar() !== ')') fail('缺少右括号', i - 1);
        return node;
      }
      if (ch === '[') return parseClass();
      if (ch === '\\') return parseEscape();
      if (ch === '.') return { type: 'set', chars: Array.from(PRINTABLE) };
      if (ch === '^' || ch === '$') { warnings.push('锚点 ^ / $ 没有实际作用，已忽略'); return { type: 'seq', items: [] }; }
      return { type: 'set', chars: [ch] };
    }

    function parseEscape() {
      var ch = nextChar();
      if (ch === undefined) fail('转义符 \\ 后缺少字符', i - 1);
      if (ch === 'd') return { type: 'set', chars: Array.from(DIGITS) };
      if (ch === 'D') return { type: 'set', chars: Array.from(complementChars(DIGITS)) };
      if (ch === 'w') return { type: 'set', chars: Array.from(LOWER + UPPER + DIGITS + '_') };
      if (ch === 'W') return { type: 'set', chars: Array.from(complementChars(LOWER + UPPER + DIGITS + '_')) };
      if (ch === 's') return { type: 'set', chars: [' ', '\t', '\r', '\n'] };
      if (ch === 'S') return { type: 'set', chars: Array.from(complementChars(' \t\r\n')) };
      if (ch === 'n') return { type: 'set', chars: ['\n'] };
      if (ch === 'r') return { type: 'set', chars: ['\r'] };
      if (ch === 't') return { type: 'set', chars: ['\t'] };
      if (ch === 'b' || ch === 'B') fail('不支持单词边界 \\b / \\B', i - 2);
      if (ch === 'p' || ch === 'P') fail('不支持 Unicode 属性类 \\p{...}', i - 2);
      if (ch === 'k') fail('不支持命名反向引用', i - 2);
      if (/^[1-9]$/.test(ch)) fail('不支持反向引用 \\' + ch, i - 2);
      if (ch === 'x' || ch === 'u') fail('不支持十六进制转义；可直接输入字符', i - 2);
      return { type: 'set', chars: [ch] };
    }

    function parseClass() {
      var negate = false;
      if (peek() === '^') { nextChar(); negate = true; }
      var parts = [];
      var first = true;
      var closed = false;
      while (i < chars.length) {
        var ch = nextChar();
        if (ch === ']' && !first) { closed = true; break; }
        first = false;
        if (ch === '\\') {
          var escaped = parseEscape();
          parts.push.apply(parts, Array.from(escaped.chars));
          continue;
        }
        if (peek() === '-' && i + 1 < chars.length && chars[i + 1] !== ']') {
          nextChar();
          var end = nextChar();
          if (end === '\\') {
            var endEscaped = parseEscape();
            var endChars = Array.from(endEscaped.chars);
            if (endChars.length !== 1) fail('字符范围终点必须是单个字符', i - 1);
            end = endChars[0];
          }
          var startCode = ch.codePointAt(0);
          var endCode = end.codePointAt(0);
          if (startCode > endCode) fail('字符范围起点大于终点', i - 1);
          for (var code = startCode; code <= endCode; code++) parts.push(String.fromCodePoint(code));
        } else {
          parts.push(ch);
        }
      }
      if (!closed) fail('字符类缺少 ]', i);
      var set = uniqueChars(parts.join(''));
      if (negate) set = complementChars(set);
      if (!set) fail('字符类为空', i);
      return { type: 'set', chars: Array.from(set) };
    }

    try {
      var ast = parseAlternation();
      if (i < chars.length) fail('存在多余的右括号 )', i);
      return { ok: true, ast: ast, warnings: warnings, unbounded: unbounded };
    } catch (error) {
      return { ok: false, error: error.message, position: error.position };
    }
  }

  function countRegex(ast, maxLength, cap) {
    var limit = clampInt(maxLength, 1, 64, 16);
    var ceiling = cap || COUNT_CAP;
    function zero() { return new Array(limit + 1).fill(0); }
    function addCapped(target, index, value) {
      var next = target[index] + value;
      target[index] = next > ceiling ? ceiling : next;
    }
    function convolve(left, right) {
      var out = zero();
      for (var a = 0; a < left.length; a++) {
        var lv = left[a];
        if (!lv) continue;
        for (var b = 0; b < right.length && a + b <= limit; b++) {
          var rv = right[b];
          if (!rv) continue;
          addCapped(out, a + b, lv * rv);
        }
      }
      return out;
    }
    function walk(node) {
      if (node.type === 'set') {
        var out = zero();
        if (limit >= 1) out[1] = Math.min(ceiling, node.chars.length);
        return out;
      }
      if (node.type === 'seq') {
        var seq = zero(); seq[0] = 1;
        node.items.forEach(function (item) { seq = convolve(seq, walk(item)); });
        return seq;
      }
      if (node.type === 'alt') {
        var alt = zero();
        node.items.forEach(function (item) {
          var part = walk(item);
          for (var k = 0; k <= limit; k++) if (part[k]) addCapped(alt, k, part[k]);
        });
        return alt;
      }
      if (node.type === 'repeat') {
        var child = walk(node.node);
        var power = zero(); power[0] = 1;
        var total = zero();
        var maxReps = Math.min(Number.isFinite(node.max) ? node.max : limit, limit);
        if (node.min === 0) total[0] += 1;
        for (var rep = 1; rep <= maxReps; rep++) {
          power = convolve(power, child);
          if (rep >= node.min) {
            for (var index = 0; index <= limit; index++) if (power[index]) addCapped(total, index, power[index]);
          }
        }
        return total;
      }
      return zero();
    }
    var byLength = walk(ast);
    var total = 0;
    var minLen = -1, maxLen = -1;
    for (var i = 0; i <= limit; i++) {
      if (byLength[i]) {
        total += byLength[i];
        if (total > ceiling) total = ceiling;
        if (minLen === -1) minLen = i;
        maxLen = i;
      }
    }
    return { byLength: byLength, total: total, capped: total >= ceiling, minLength: minLen, maxLength: maxLen, limit: limit };
  }

  function regexGenerator(ast, maxLength) {
    var limit = clampInt(maxLength, 1, 64, 16);
    function* genNode(node, prefix) {
      if (prefix.length > limit) return;
      if (node.type === 'set') {
        for (var i = 0; i < node.chars.length; i++) {
          var value = prefix + node.chars[i];
          if (value.length <= limit) yield value;
        }
        return;
      }
      if (node.type === 'seq') {
        yield* genSequence(node.items, 0, prefix);
        return;
      }
      if (node.type === 'alt') {
        for (var a = 0; a < node.items.length; a++) yield* genNode(node.items[a], prefix);
        return;
      }
      if (node.type === 'repeat') {
        var maxReps = Math.min(Number.isFinite(node.max) ? node.max : limit, limit);
        yield* genRepeat(node, 0, prefix, maxReps);
      }
    }
    function* genSequence(items, index, prefix) {
      if (index >= items.length) { yield prefix; return; }
      for (var value of genNode(items[index], prefix)) yield* genSequence(items, index + 1, value);
    }
    function* genRepeat(node, count, prefix, maxReps) {
      if (count >= node.min) yield prefix;
      if (count >= maxReps || prefix.length >= limit) return;
      for (var value of genNode(node.node, prefix)) yield* genRepeat(node, count + 1, value, maxReps);
    }
    return genNode(ast, '');
  }

  function sampleRegex(ast, maxLength, limit) {
    var out = [];
    var iterator = regexGenerator(ast, maxLength);
    while (out.length < limit) {
      var next = iterator.next();
      if (next.done) break;
      out.push(next.value);
    }
    return out;
  }

  /* ------------------------------------------------------------------ *
   * Constraints
   * ------------------------------------------------------------------ */

  function optionalLength(value) {
    if (value === null || value === undefined) return null;
    if (String(value).trim() === '') return null;
    var n = Number(value);
    return Number.isFinite(n) ? clampInt(n, 0, 64, 0) : null;
  }

  function normalizeConstraints(input) {
    input = input || {};
    var contains = (Array.isArray(input.contains) ? input.contains : String(input.contains || '').split(/\r?\n/))
      .map(function (value) { return String(value); })
      .filter(function (value) { return value.length > 0; });
    var constraints = {
      minLength: optionalLength(input.minLength),
      maxLength: optionalLength(input.maxLength),
      requireLower: !!input.requireLower,
      requireUpper: !!input.requireUpper,
      requireDigit: !!input.requireDigit,
      requireSymbol: !!input.requireSymbol,
      contains: contains,
      containsMode: input.containsMode === 'all' ? 'all' : 'any',
      ignoreCase: !!input.ignoreCase,
      requireAny: uniqueChars(input.requireAny || ''),
      requireAll: uniqueChars(input.requireAll || ''),
      exclude: uniqueChars(input.exclude || '')
    };
    if (constraints.minLength !== null && constraints.maxLength !== null && constraints.minLength > constraints.maxLength) {
      var swap = constraints.minLength;
      constraints.minLength = constraints.maxLength;
      constraints.maxLength = swap;
    }
    return constraints;
  }

  function hasConstraints(constraints) {
    if (!constraints) return false;
    return constraints.minLength !== null || constraints.maxLength !== null ||
      constraints.requireLower || constraints.requireUpper || constraints.requireDigit || constraints.requireSymbol ||
      constraints.contains.length > 0 || constraints.requireAny.length > 0 ||
      constraints.requireAll.length > 0 || constraints.exclude.length > 0;
  }

  function constraintsPass(candidate, constraints) {
    if (!constraints || !hasConstraints(constraints)) return true;
    var value = String(candidate);
    if (constraints.minLength !== null && value.length < constraints.minLength) return false;
    if (constraints.maxLength !== null && value.length > constraints.maxLength) return false;

    var hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
    var anyFound = constraints.requireAny.length === 0;
    var allNeeded = new Set(Array.from(constraints.requireAll));
    var exclude = new Set(Array.from(constraints.exclude));
    for (var ch of value) {
      if (ch >= 'a' && ch <= 'z') hasLower = true;
      else if (ch >= 'A' && ch <= 'Z') hasUpper = true;
      else if (ch >= '0' && ch <= '9') hasDigit = true;
      if (SYMBOLS.indexOf(ch) !== -1) hasSymbol = true;
      if (exclude.has(ch)) return false;
      if (allNeeded.has(ch)) allNeeded.delete(ch);
      if (!anyFound && constraints.requireAny.indexOf(ch) !== -1) anyFound = true;
    }
    if (constraints.requireLower && !hasLower) return false;
    if (constraints.requireUpper && !hasUpper) return false;
    if (constraints.requireDigit && !hasDigit) return false;
    if (constraints.requireSymbol && !hasSymbol) return false;
    if (!anyFound) return false;
    if (allNeeded.size) return false;

    if (constraints.contains.length) {
      var haystack = constraints.ignoreCase ? value.toLowerCase() : value;
      var found = 0;
      for (var needle of constraints.contains) {
        var target = constraints.ignoreCase ? needle.toLowerCase() : needle;
        if (haystack.indexOf(target) !== -1) {
          found++;
          if (constraints.containsMode === 'any') break;
        }
      }
      if (constraints.containsMode === 'any' && found === 0) return false;
      if (constraints.containsMode === 'all' && found !== constraints.contains.length) return false;
    }
    return true;
  }

  function constraintSummary(constraints) {
    if (!constraints || !hasConstraints(constraints)) return [];
    var out = [];
    if (constraints.minLength !== null || constraints.maxLength !== null) {
      out.push('长度 ' + (constraints.minLength === null ? 0 : constraints.minLength) + '–' + (constraints.maxLength === null ? '∞' : constraints.maxLength));
    }
    var required = [];
    if (constraints.requireLower) required.push('小写');
    if (constraints.requireUpper) required.push('大写');
    if (constraints.requireDigit) required.push('数字');
    if (constraints.requireSymbol) required.push('符号');
    if (required.length) out.push('包含' + required.join('/'));
    if (constraints.contains.length) out.push('子串' + (constraints.containsMode === 'all' ? '全部' : '任一') + (constraints.ignoreCase ? '（忽略大小写）' : '') + '：' + constraints.contains.join(' | '));
    if (constraints.requireAny) out.push('任一字符：' + constraints.requireAny);
    if (constraints.requireAll) out.push('全部字符：' + constraints.requireAll);
    if (constraints.exclude) out.push('排除：' + constraints.exclude);
    return out;
  }

  /* ------------------------------------------------------------------ *
   * Word rules
   * ------------------------------------------------------------------ */

  var YEARS = ['2020', '2021', '2022', '2023', '2024', '2025', '2026'];

  function reverseText(value) { return Array.from(String(value)).reverse().join(''); }

  function leetText(value) {
    var map = { a: '@', e: '3', i: '1', o: '0', s: '$', t: '7', g: '9', b: '8' };
    return String(value).replace(/[aeiostgbAEIOSTGB]/g, function (ch) { return map[ch.toLowerCase()]; });
  }

  function baseTransform(value, base) {
    if (base === 'lower') return value.toLowerCase();
    if (base === 'upper') return value.toUpperCase();
    if (base === 'capitalize') { var chars = Array.from(value); return chars.length ? chars[0].toUpperCase() + chars.slice(1).join('').toLowerCase() : value; }
    return value;
  }

  function variantsForWord(word, rules) {
    rules = rules || {};
    var base = rules.trim ? String(word).trim() : String(word);
    base = baseTransform(base, rules.base || 'none');
    var variants = new Set([base]);
    if (rules.reverse) Array.from(variants).forEach(function (value) { variants.add(reverseText(value)); });
    if (rules.duplicate) Array.from(variants).forEach(function (value) { variants.add(value + value); });
    if (rules.leet) Array.from(variants).forEach(function (value) { variants.add(leetText(value)); });
    var prefixes = [rules.prefix || ''].concat(rules.prependChars ? Array.from(rules.prependChars) : []);
    var suffixes = [rules.suffix || ''].concat(rules.appendChars ? Array.from(rules.appendChars) : []);
    if (rules.years) suffixes = suffixes.concat(YEARS);
    Array.from(variants).forEach(function (value) {
      prefixes.forEach(function (prefix) { if (prefix) variants.add(prefix + value); });
      suffixes.forEach(function (suffix) { if (suffix) variants.add(value + suffix); });
    });
    return Array.from(variants);
  }

  function variantEstimate(rules) {
    return variantsForWord('Password1', rules).length;
  }

  function rulesActive(rules) {
    rules = rules || {};
    return (rules.base && rules.base !== 'none') || rules.reverse || rules.duplicate || rules.leet || rules.trim ||
      !!(rules.prefix || rules.suffix || rules.appendChars || rules.prependChars || rules.years);
  }

  /* ------------------------------------------------------------------ *
   * Hash parsing and command building
   * ------------------------------------------------------------------ */

  function isHex(value) { return /^[0-9a-f]+$/i.test(value); }

  function stripBom(text) {
    var value = String(text || '');
    return value.charCodeAt(0) === 0xFEFF ? value.slice(1) : value;
  }

  function makeUnsaltedTarget(mode, hash) {
    var definition = MODES[mode];
    var value = String(hash).toLowerCase();
    return { key: mode + '|' + value, mode: mode, kind: 'unsalted', algorithm: definition.algorithm, hash: value, display: value };
  }

  function makeSaltedTarget(mode, hash, salt) {
    var definition = MODES[mode];
    var value = String(hash).toLowerCase();
    var saltValue = String(salt);
    return {
      key: mode + '|' + value + '|' + saltValue,
      mode: mode,
      kind: 'salted',
      algorithm: definition.algorithm,
      saltPosition: definition.saltPosition,
      hash: value,
      salt: saltValue,
      display: value + ':' + saltValue
    };
  }

  function makeBcryptTarget(hash) {
    return { key: 'BCRYPT|' + hash, mode: 'BCRYPT', kind: 'bcrypt', hash: hash, display: hash };
  }

  function parseNetNTLMv2Line(raw) {
    var value = String(raw || '').trim();
    var parts = value.split(':');
    var username, domain, challenge, proof, blob;
    if (parts.length === 6 && parts[1] === '') {
      username = parts[0]; domain = parts[2]; challenge = parts[3]; proof = parts[4]; blob = parts[5];
    } else if (parts.length === 5) {
      username = parts[0]; domain = parts[1]; challenge = parts[2]; proof = parts[3]; blob = parts[4];
    } else {
      return { ok: false, error: 'NetNTLMv2 格式应为 user::domain:challenge:NTProofStr:blob' };
    }
    if (!username) return { ok: false, error: 'NetNTLMv2 缺少用户名' };
    if (!/^[0-9a-f]{16}$/i.test(challenge)) return { ok: false, error: 'NetNTLMv2 的 ServerChallenge 应为 16 位十六进制（8 字节）' };
    if (!/^[0-9a-f]{32}$/i.test(proof)) return { ok: false, error: 'NetNTLMv2 的 NTProofStr 应为 32 位十六进制（16 字节）' };
    if (!blob || blob.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(blob)) return { ok: false, error: 'NetNTLMv2 的 Blob 应为偶数长度的十六进制' };
    challenge = challenge.toLowerCase();
    proof = proof.toLowerCase();
    blob = blob.toLowerCase();
    var display = username + '::' + domain + ':' + challenge + ':' + proof + ':' + blob;
    return {
      ok: true,
      target: {
        key: 'NETNTLMv2|' + display,
        mode: 'NETNTLMv2',
        kind: 'netntlmv2',
        username: username,
        domain: domain,
        challenge: challenge,
        proof: proof,
        blob: blob,
        display: display
      }
    };
  }

  function parseDcc2Line(raw) {
    var value = String(raw || '').trim();
    var marker = value.indexOf('$DCC2$');
    if (marker === -1) return { ok: false, error: 'DCC2 格式应为 $DCC2$10240#user#hash' };
    value = value.slice(marker);
    var match = /^\$DCC2\$(\d+)#([^#]+)#([0-9a-f]{32})$/i.exec(value);
    if (!match) return { ok: false, error: 'DCC2 格式应为 $DCC2$10240#user#hash（32 位十六进制结果）' };
    var iterations = Number(match[1]);
    if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 1000000) {
      return { ok: false, error: 'DCC2 迭代次数应在 1–1,000,000 之间（常见为 10240）' };
    }
    var username = match[2].trim();
    if (!username) return { ok: false, error: 'DCC2 缺少用户名' };
    var hash = match[3].toLowerCase();
    var display = '$DCC2$' + iterations + '#' + username + '#' + hash;
    return {
      ok: true,
      target: {
        key: 'DCC2|' + display,
        mode: 'DCC2',
        kind: 'dcc2',
        username: username,
        iterations: iterations,
        hash: hash,
        display: display
      }
    };
  }

  function parseTargetForMode(raw, mode, globalSalt) {
    var definition = MODES[mode];
    if (!definition) return { ok: false, error: '不支持的哈希模式' };
    if (definition.kind === 'bcrypt') {
      if (!BCRYPT_RE.test(raw)) return { ok: false, error: 'bcrypt 格式不正确（应为 $2a$ / $2b$ / $2y$ + 成本 + 53 位字符）' };
      return { ok: true, target: makeBcryptTarget(raw) };
    }
    if (definition.kind === 'netntlmv2') return parseNetNTLMv2Line(raw);
    if (definition.kind === 'dcc2') return parseDcc2Line(raw);
    if (definition.kind === 'salted') {
      var hashPart = raw;
      var salt = null;
      var colon = raw.indexOf(':');
      if (colon !== -1) {
        hashPart = raw.slice(0, colon);
        salt = raw.slice(colon + 1);
        if (!salt) return { ok: false, error: 'Salt 为空；请写成 hash:salt，或填写全局 Salt' };
      } else if (globalSalt !== null && globalSalt !== undefined && String(globalSalt).length > 0) {
        salt = String(globalSalt);
      } else {
        return { ok: false, error: '带盐模式需要 hash:salt，或填写全局 Salt' };
      }
      if (!isHex(hashPart) || hashPart.length !== definition.hexLength) {
        return { ok: false, error: '哈希不是 ' + definition.hexLength + ' 位十六进制字符串' };
      }
      return { ok: true, target: makeSaltedTarget(mode, hashPart, salt) };
    }
    if (raw.indexOf(':') !== -1) return { ok: false, error: '该模式不带 salt；请选择带盐模式，或删除哈希行中的冒号' };
    if (!isHex(raw) || raw.length !== definition.hexLength) {
      return { ok: false, error: '不是 ' + definition.hexLength + ' 位十六进制字符串' };
    }
    return { ok: true, target: makeUnsaltedTarget(mode, raw) };
  }

  function detectMode(value) {
    var raw = String(value || '').trim();
    if (BCRYPT_RE.test(raw)) return 'BCRYPT';
    if (raw.indexOf('$DCC2$') !== -1) return parseDcc2Line(raw).ok ? 'DCC2' : null;
    if (parseNetNTLMv2Line(raw).ok) return 'NETNTLMv2';
    if (!isHex(raw)) return null;
    return HEX_LENGTH_MODE[raw.length] || null;
  }

  function parseHashLines(text, selectedMode, globalSalt) {
    selectedMode = selectedMode || 'AUTO';
    var targets = new Map();
    var invalid = [];
    var counts = {};
    var ambiguous32 = 0;
    stripBom(text).split(/\r?\n/).forEach(function (line, index) {
      var raw = line.trim();
      if (!raw) return;
      var target = null;
      var reason = null;
      if (selectedMode === 'AUTO') {
        if (BCRYPT_RE.test(raw)) {
          target = makeBcryptTarget(raw);
        } else if (raw.indexOf('$DCC2$') !== -1) {
          var dcc2 = parseDcc2Line(raw);
          if (dcc2.ok) target = dcc2.target; else reason = dcc2.error;
        } else {
          var netntlm = parseNetNTLMv2Line(raw);
          if (netntlm.ok) {
            target = netntlm.target;
          } else {
            var detected = detectMode(raw);
            if (detected) {
              var autoParsed = parseTargetForMode(raw, detected, globalSalt);
              if (autoParsed.ok) target = autoParsed.target; else reason = autoParsed.error;
            } else if (raw.indexOf('::') !== -1) {
              reason = 'NetNTLMv2 格式不正确：user::domain:challenge:NTProofStr:blob';
            } else if (raw.indexOf(':') !== -1) {
              reason = '检测到冒号；带 salt 的哈希请先选择对应的“带盐”模式，或使用“全局 Salt”';
            } else if (/^[0-9a-f]{96}$/i.test(raw)) {
              reason = '暂不支持 SHA-384';
            } else {
              reason = '无法自动识别；支持无盐 MD5/SHA/NTLM、bcrypt、NetNTLMv2 和 $DCC2$';
            }
          }
        }
      } else {
        var parsed = parseTargetForMode(raw, selectedMode, globalSalt);
        if (parsed.ok) target = parsed.target; else reason = parsed.error;
      }
      if (reason || !target) {
        invalid.push({ line: index + 1, value: raw, reason: reason || '无法解析该哈希' });
        return;
      }
      if (selectedMode === 'AUTO' && target.mode === 'MD5' && target.hash && target.hash.length === 32) ambiguous32++;
      if (!targets.has(target.key)) {
        targets.set(target.key, target);
        counts[target.mode] = (counts[target.mode] || 0) + 1;
      }
    });
    return { targets: targets, invalid: invalid, counts: counts, ambiguous32: ambiguous32 };
  }

  function shellQuote(value) {
    return "'" + String(value).replace(/'/g, "'\\''") + "'";
  }

  function modeHashcatValue(mode) {
    return MODES[mode] ? String(MODES[mode].hashcat) : '<模式>';
  }

  function hashcatCommand(input) {
    input = input || {};
    var modes = (input.modes || []).filter(function (mode) { return MODES[mode]; });
    var modeValues = modes.length ? modes : ['<模式>'];
    var lines = [];
    var custom = input.customSets || [];
    var csOptions = '';
    (input.customUsed || []).forEach(function (index) {
      csOptions += ' -' + (index + 1) + ' ' + shellQuote(String(custom[index] || ''));
    });
    var constraints = input.constraints;
    var definitions = modes.map(function (mode) { return MODES[mode]; }).filter(Boolean);
    if (definitions.some(function (definition) { return definition.kind === 'salted'; })) {
      lines.push('# 带盐模式：hash.txt 每行使用 hash:salt；若本页使用了全局 Salt，请先把它写入每一行。');
    }
    if (definitions.some(function (definition) { return definition.key === 'NETNTLMv2'; })) {
      lines.push('# NetNTLMv2 行格式：user::domain:challenge:NTProofStr:blob；HashCat 直接读取整行。');
    }
    if (definitions.some(function (definition) { return definition.key === 'DCC2'; })) {
      lines.push('# DCC2 行格式：$DCC2$10240#user#hash；浏览器 PBKDF2 验证通常比 MD5/SHA 慢很多。');
    }
    if (constraints && hasConstraints(constraints)) {
      lines.push('# 本页“密码特征约束”没有等价的 hashcat 参数，hashcat 可能会多尝试一些候选。');
    }
    modeValues.forEach(function (mode) {
      var m = input.modeOverride || mode;
      if (input.attack === 'mask') {
        if (!input.mask) { lines.push('hashcat -m ' + modeHashcatValue(m) + ' -a 3 hash.txt \'?l?l?l?l\''); return; }
        lines.push('hashcat -m ' + modeHashcatValue(m) + ' -a 3' + csOptions + ' hash.txt ' + shellQuote(input.mask));
      } else if (input.attack === 'dict') {
        if (rulesActive(input.rules)) {
          lines.push('# 本页的规则是可视化近似；HashCat 规则文件可按教程替换为 best64.rule 等。');
        }
        lines.push('hashcat -m ' + modeHashcatValue(m) + ' -a 0 hash.txt dict.txt' + (rulesActive(input.rules) ? ' -r best64.rule' : ''));
      } else if (input.attack === 'hybrid') {
        var mask = input.mask || '?d?d';
        var hybridRules = rulesActive(input.rules);
        if (hybridRules) lines.push('# 本页的规则是可视化近似；HashCat 规则文件可按教程替换为 best64.rule 等。');
        lines.push('hashcat -m ' + modeHashcatValue(m) + ' -a ' + (input.direction === 'prefix' ? 7 : 6) + csOptions +
          (hybridRules ? ' -r best64.rule' : '') + ' hash.txt ' +
          (input.direction === 'prefix' ? shellQuote(mask) + ' dict.txt' : 'dict.txt ' + shellQuote(mask)));
      } else if (input.attack === 'regex') {
        lines.push('# HashCat 没有正则攻击模式；可先把正则展开为候选词，再执行：');
        lines.push('hashcat -m ' + modeHashcatValue(m) + ' -a 0 hash.txt candidates.txt');
      }
    });
    if (input.attack === 'regex') lines.push('# 提示：也可用 hashcat --stdout -a 3 ... 生成掩码候选，再配合 shell 工具筛选。');
    return lines.join('\n');
  }

  var api = {
    LOWER: LOWER, UPPER: UPPER, DIGITS: DIGITS, SYMBOLS: SYMBOLS,
    PRINTABLE: PRINTABLE, ALL: ALL, HEX_LOWER: HEX_LOWER, HEX_UPPER: HEX_UPPER,
    MODES: MODES, BLOCK_LABELS: BLOCK_LABELS, BLOCK_TOKENS: BLOCK_TOKENS,
    YEARS: YEARS, COUNT_CAP: COUNT_CAP,
    uniqueChars: uniqueChars,
    clampInt: clampInt,
    formatCount: formatCount,
    formatDuration: formatDuration,
    md5: md5,
    md4: md4,
    ntlm: ntlm,
    hexOf: hexOf,
    hexToBytes: hexToBytes,
    utf16leBytes: utf16leBytes,
    concatBytes: concatBytes,
    hmacMd5: hmacMd5,
    expandCustomSet: expandCustomSet,
    maskFromBlocks: maskFromBlocks,
    compileMask: compileMask,
    buildMaskBatch: buildMaskBatch,
    parseRegex: parseRegex,
    countRegex: countRegex,
    regexGenerator: regexGenerator,
    sampleRegex: sampleRegex,
    normalizeConstraints: normalizeConstraints,
    hasConstraints: hasConstraints,
    constraintsPass: constraintsPass,
    constraintSummary: constraintSummary,
    variantsForWord: variantsForWord,
    variantEstimate: variantEstimate,
    rulesActive: rulesActive,
    detectMode: detectMode,
    parseNetNTLMv2Line: parseNetNTLMv2Line,
    parseDcc2Line: parseDcc2Line,
    parseHashLines: parseHashLines,
    shellQuote: shellQuote,
    hashcatCommand: hashcatCommand
  };
  return api;
});
