/*
 * APK 静态检查：字节读取、流式摘要与 ZIP 目录解析。
 * 该文件是普通浏览器脚本，按顺序加载后通过 globalThis.ApkInspect 共享命名空间；
 * Node 测试中也可以通过 require 依次加载同一组文件。
 */
(() => {
  'use strict';

  const root = typeof globalThis !== 'undefined' ? globalThis : window;
  const Api = root.ApkInspect = root.ApkInspect || {};
  const MAX_FILE_SIZE = 1024 * 1024 * 1024;

  /* ------------------------------------------------------------------ */
  /* 基础字节工具                                                         */
  /* ------------------------------------------------------------------ */

  function readU16(bytes, offset) {
    return bytes[offset] | (bytes[offset + 1] << 8);
  }
  function readU32(bytes, offset) {
    return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
  }
  function readU32BE(bytes, offset) {
    return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
  }
  function readU64(bytes, offset) {
    const lo = readU32(bytes, offset);
    const hi = readU32(bytes, offset + 4);
    return hi * 4294967296 + lo;
  }
  function writeU32(bytes, offset, value) {
    bytes[offset] = value & 0xff;
    bytes[offset + 1] = (value >>> 8) & 0xff;
    bytes[offset + 2] = (value >>> 16) & 0xff;
    bytes[offset + 3] = (value >>> 24) & 0xff;
  }
  function writeU32BE(bytes, offset, value) {
    bytes[offset] = (value >>> 24) & 0xff;
    bytes[offset + 1] = (value >>> 16) & 0xff;
    bytes[offset + 2] = (value >>> 8) & 0xff;
    bytes[offset + 3] = value & 0xff;
  }
  function hex(bytes) {
    return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('').toUpperCase();
  }
  function utf8(bytes) {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }
  function isPrintableText(bytes) {
    if (!bytes.length) return true;
    let control = 0;
    const limit = Math.min(bytes.length, 4096);
    for (let i = 0; i < limit; i++) {
      const byte = bytes[i];
      if (byte === 0) { control += 4; continue; }
      if (byte < 0x09 || (byte > 0x0d && byte < 0x20) || byte === 0x7f) control++;
    }
    return control / limit < 0.05;
  }
  function cstring(bytes, offset, limit) {
    let end = offset;
    const stop = Math.min(bytes.length, offset + (limit || 4096));
    while (end < stop && bytes[end] !== 0) end++;
    return utf8(bytes.subarray(offset, end));
  }
  function adler32(bytes) {
    let a = 1, b = 0;
    const mod = 65521;
    for (let i = 0; i < bytes.length;) {
      const end = Math.min(i + 3800, bytes.length);
      for (; i < end; i++) { a += bytes[i]; b += a; }
      a %= mod; b %= mod;
    }
    return ((b << 16) | a) >>> 0;
  }
  function formatBytes(value) {
    if (!Number.isFinite(value)) return '—';
    const units = ['B', 'KiB', 'MiB', 'GiB'];
    let index = 0, size = value;
    while (size >= 1024 && index < units.length - 1) { size /= 1024; index++; }
    return (index === 0 ? String(size) : size.toFixed(size >= 100 ? 0 : size >= 10 ? 1 : 2)) + ' ' + units[index];
  }
  function sourceFromBytes(bytes, name) {
    // Buffer 是 Uint8Array 的子类，但其 slice() 返回共享视图；先规范为普通 Uint8Array。
    const view = bytes instanceof Uint8Array
      ? new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
      : new Uint8Array(bytes);
    return {
      name: name || 'memory.apk',
      size: view.length,
      lastModified: 0,
      async slice(start, end) {
        const part = view.subarray(start, end);
        return { arrayBuffer: async () => new Uint8Array(part).buffer, size: part.length };
      }
    };
  }
  async function readRange(source, start, length) {
    if (start < 0 || length < 0 || start + length > source.size) {
      throw new Error('读取范围超出文件长度：' + start + ' + ' + length + ' > ' + source.size);
    }
    const blob = await source.slice(start, start + length);
    return new Uint8Array(await blob.arrayBuffer());
  }
  function checkSource(source) {
    if (!source || typeof source.size !== 'number' || typeof source.slice !== 'function') throw new Error('缺少可读取的文件对象。');
    if (source.size <= 0) throw new Error('文件为空。');
    if (source.size > MAX_FILE_SIZE) throw new Error('文件超过 1 GiB 限制。');
  }

  /* ------------------------------------------------------------------ */
  /* MD5 / SHA-1 / SHA-256（流式，用于整包与条目摘要）                    */
  /* ------------------------------------------------------------------ */

  class BlockHasher {
    constructor(blockSize) {
      this.blockSize = blockSize;
      this.buffer = new Uint8Array(blockSize);
      this.bufferLength = 0;
      this.total = 0;
    }
    update(data) {
      const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
      this.total += bytes.length;
      let offset = 0;
      if (this.bufferLength) {
        const need = this.blockSize - this.bufferLength;
        const take = Math.min(need, bytes.length);
        this.buffer.set(bytes.subarray(0, take), this.bufferLength);
        this.bufferLength += take;
        offset = take;
        if (this.bufferLength === this.blockSize) {
          this.compress(this.buffer, 0);
          this.bufferLength = 0;
        }
      }
      while (offset + this.blockSize <= bytes.length) {
        this.compress(bytes, offset);
        offset += this.blockSize;
      }
      if (offset < bytes.length) {
        this.buffer.set(bytes.subarray(offset), 0);
        this.bufferLength = bytes.length - offset;
      }
      return this;
    }
    finalize() {
      const blockSize = this.blockSize;
      const tail = new Uint8Array(blockSize * 2);
      tail.set(this.buffer.subarray(0, this.bufferLength), 0);
      tail[this.bufferLength] = 0x80;
      let length = this.bufferLength + 1 <= blockSize - 8 ? blockSize : blockSize * 2;
      const bitLengthLow = (this.total * 8) >>> 0;
      const bitLengthHigh = Math.floor(this.total / 536870912) >>> 0;
      // 64 位长度写在最后 8 字节，MD5 使用小端，SHA 使用大端。
      if (this.littleEndianLength) {
        writeU32(tail, length - 8, bitLengthLow);
        writeU32(tail, length - 4, bitLengthHigh);
      } else {
        writeU32BE(tail, length - 8, bitLengthHigh);
        writeU32BE(tail, length - 4, bitLengthLow);
      }
      this.compress(tail, 0);
      if (length === blockSize * 2) this.compress(tail, blockSize);
      return this.digestBytes();
    }
  }

  const MD5_K = new Int32Array([
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
  ]);
  const MD5_S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

  class Md5 extends BlockHasher {
    constructor() {
      super(64);
      this.littleEndianLength = true;
      this.h = new Int32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
      this.w = new Int32Array(16);
    }
    compress(bytes, offset) {
      const w = this.w;
      for (let i = 0; i < 16; i++) w[i] = readU32(bytes, offset + i * 4);
      let a = this.h[0], b = this.h[1], c = this.h[2], d = this.h[3];
      for (let i = 0; i < 64; i++) {
        let f, g;
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
        else { f = c ^ (b | ~d); g = (7 * i) & 15; }
        const sum = (a + f + MD5_K[i] + w[g]) | 0;
        const shift = MD5_S[(i >> 4) * 4 + (i & 3)];
        a = d; d = c; c = b;
        b = (b + ((sum << shift) | (sum >>> (32 - shift)))) | 0;
      }
      this.h[0] = (this.h[0] + a) | 0;
      this.h[1] = (this.h[1] + b) | 0;
      this.h[2] = (this.h[2] + c) | 0;
      this.h[3] = (this.h[3] + d) | 0;
    }
    digestBytes() {
      const out = new Uint8Array(16);
      for (let i = 0; i < 4; i++) writeU32(out, i * 4, this.h[i] >>> 0);
      return out;
    }
  }

  class Sha1 extends BlockHasher {
    constructor() {
      super(64);
      this.h = new Int32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
      this.w = new Int32Array(80);
    }
    compress(bytes, offset) {
      const w = this.w;
      for (let i = 0; i < 16; i++) w[i] = readU32BE(bytes, offset + i * 4);
      for (let i = 16; i < 80; i++) {
        const value = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (value << 1) | (value >>> 31);
      }
      let a = this.h[0], b = this.h[1], c = this.h[2], d = this.h[3], e = this.h[4];
      for (let i = 0; i < 80; i++) {
        let f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) | 0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = temp;
      }
      this.h[0] = (this.h[0] + a) | 0;
      this.h[1] = (this.h[1] + b) | 0;
      this.h[2] = (this.h[2] + c) | 0;
      this.h[3] = (this.h[3] + d) | 0;
      this.h[4] = (this.h[4] + e) | 0;
    }
    digestBytes() {
      const out = new Uint8Array(20);
      for (let i = 0; i < 5; i++) writeU32BE(out, i * 4, this.h[i] >>> 0);
      return out;
    }
  }

  const SHA256_K = new Int32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  class Sha256 extends BlockHasher {
    constructor() {
      super(64);
      this.h = new Int32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
      ]);
      this.w = new Int32Array(64);
    }
    compress(bytes, offset) {
      const w = this.w;
      for (let i = 0; i < 16; i++) w[i] = readU32BE(bytes, offset + i * 4);
      for (let i = 16; i < 64; i++) {
        const w15 = w[i - 15];
        const w2 = w[i - 2];
        const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
        const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let a = this.h[0], b = this.h[1], c = this.h[2], d = this.h[3];
      let e = this.h[4], f = this.h[5], g = this.h[6], h = this.h[7];
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + temp1) | 0;
        d = c; c = b; b = a; a = (temp1 + temp2) | 0;
      }
      this.h[0] = (this.h[0] + a) | 0;
      this.h[1] = (this.h[1] + b) | 0;
      this.h[2] = (this.h[2] + c) | 0;
      this.h[3] = (this.h[3] + d) | 0;
      this.h[4] = (this.h[4] + e) | 0;
      this.h[5] = (this.h[5] + f) | 0;
      this.h[6] = (this.h[6] + g) | 0;
      this.h[7] = (this.h[7] + h) | 0;
    }
    digestBytes() {
      const out = new Uint8Array(32);
      for (let i = 0; i < 8; i++) writeU32BE(out, i * 4, this.h[i] >>> 0);
      return out;
    }
  }

  function digestBytes(kind, bytes) {
    const hasher = kind === 'md5' ? new Md5() : kind === 'sha1' ? new Sha1() : new Sha256();
    hasher.update(bytes);
    return hasher.finalize();
  }
  const hashApi = {
    Md5, Sha1, Sha256,
    create(kind) {
      if (kind === 'md5') return new Md5();
      if (kind === 'sha1') return new Sha1();
      if (kind === 'sha256') return new Sha256();
      throw new Error('不支持的摘要算法：' + kind);
    },
    digest(kind, bytes) { return digestBytes(kind, bytes); },
    hex(kind, bytes) { return hex(digestBytes(kind, bytes)); },
    async hashSource(source, options = {}) {
      const kinds = options.kinds || ['md5', 'sha1', 'sha256'];
      const chunkSize = options.chunkSize || 4 * 1024 * 1024;
      const hashers = kinds.map(kind => ({ kind, hasher: hashApi.create(kind) }));
      let offset = 0;
      const startedAt = Date.now();
      while (offset < source.size) {
        if (options.signal?.aborted) throw new DOMException('已取消', 'AbortError');
        const end = Math.min(offset + chunkSize, source.size);
        const chunk = await readRange(source, offset, end - offset);
        for (const item of hashers) item.hasher.update(chunk);
        offset = end;
        options.onProgress?.({ bytesRead: offset, total: source.size, percent: Math.floor(offset / source.size * 100) });
      }
      const result = {};
      for (const item of hashers) result[item.kind] = hex(item.hasher.finalize());
      result.bytes = source.size;
      result.milliseconds = Date.now() - startedAt;
      return result;
    }
  };

  /* ------------------------------------------------------------------ */
  /* ZIP 中央目录                                                         */
  /* ------------------------------------------------------------------ */

  const MAX_ENTRIES = 60000;
  const MAX_CENTRAL_DIRECTORY = 64 * 1024 * 1024;

  function decodeZipName(bytes, flags, extra) {
    if (flags & 0x800) return utf8(bytes);
    // Unicode Path Extra Field (0x7075)：版本 1 + 名称 CRC32 + UTF-8 名称
    for (const field of extra) {
      if (field.id !== 0x7075 || field.data.length < 5 || field.data[0] !== 1) continue;
      return utf8(field.data.subarray(5));
    }
    return utf8(bytes);
  }
  function parseExtraFields(bytes) {
    const fields = [];
    let offset = 0;
    while (offset + 4 <= bytes.length) {
      const id = readU16(bytes, offset);
      const size = readU16(bytes, offset + 2);
      if (offset + 4 + size > bytes.length) break;
      fields.push({ id, data: bytes.subarray(offset + 4, offset + 4 + size) });
      offset += 4 + size;
    }
    return fields;
  }
  function dosDateTime(dateValue, timeValue) {
    const year = 1980 + ((dateValue >> 9) & 0x7f);
    const month = (dateValue >> 5) & 0x0f;
    const day = dateValue & 0x1f;
    const hour = (timeValue >> 11) & 0x1f;
    const minute = (timeValue >> 5) & 0x3f;
    const second = (timeValue & 0x1f) * 2;
    if (!month || !day) return { text: '', unix: null };
    const pad = value => String(value).padStart(2, '0');
    const text = year + '-' + pad(month) + '-' + pad(day) + ' ' + pad(hour) + ':' + pad(minute) + ':' + pad(second);
    return { text, unix: Date.UTC(year, month - 1, day, hour, minute, second) };
  }
  function extendedTimestamp(extra) {
    for (const field of extra) {
      if (field.id !== 0x5455 || field.data.length < 5) continue;
      const flags = field.data[0];
      if (!(flags & 1) || field.data.length < 5) continue;
      return readU32(field.data, 1) * 1000;
    }
    return null;
  }
  function zip64Values(entry, extra, needs) {
    for (const field of extra) {
      if (field.id !== 0x0001) continue;
      const data = field.data;
      let offset = 0;
      for (const name of needs) {
        if (name === 'size' && offset + 8 <= data.length) { entry.size = readU64(data, offset); offset += 8; }
        else if (name === 'compressedSize' && offset + 8 <= data.length) { entry.compressedSize = readU64(data, offset); offset += 8; }
        else if (name === 'localHeaderOffset' && offset + 8 <= data.length) { entry.localHeaderOffset = readU64(data, offset); offset += 8; }
        else if (name === 'diskStart' && offset + 4 <= data.length) { entry.diskStart = readU32(data, offset); offset += 4; }
      }
    }
  }

  async function findEndOfCentralDirectory(source) {
    const tailLength = Math.min(source.size, 22 + 65535 + 20);
    const tailStart = source.size - tailLength;
    const tail = await readRange(source, tailStart, tailLength);
    for (let offset = tail.length - 22; offset >= 0; offset--) {
      if (readU32(tail, offset) !== 0x06054b50) continue;
      const commentLength = readU16(tail, offset + 20);
      if (offset + 22 + commentLength > tail.length) continue;
      const info = {
        eocdOffset: tailStart + offset,
        entryCount: readU16(tail, offset + 10),
        cdSize: readU32(tail, offset + 12),
        cdOffset: readU32(tail, offset + 16),
        comment: tail.subarray(offset + 22, offset + 22 + commentLength),
        zip64: false
      };
      if (info.entryCount === 0xffff || info.cdSize === 0xffffffff || info.cdOffset === 0xffffffff) {
        const locatorOffset = offset - 20;
        if (locatorOffset >= 0 && readU32(tail, locatorOffset) === 0x07064b50) {
          const zip64Offset = readU64(tail, locatorOffset + 8);
          const record = await readRange(source, zip64Offset, 56);
          if (readU32(record, 0) === 0x06064b50) {
            info.zip64 = true;
            info.entryCount = readU64(record, 32);
            info.cdSize = readU64(record, 40);
            info.cdOffset = readU64(record, 48);
          }
        }
      }
      return info;
    }
    return null;
  }

  async function readDirectory(source, options = {}) {
    checkSource(source);
    const eocd = await findEndOfCentralDirectory(source);
    if (!eocd) throw new Error('没有找到 ZIP 中央目录结束记录，文件可能不是有效的 APK/ZIP。');
    if (eocd.cdOffset + eocd.cdSize > source.size) throw new Error('ZIP 中央目录偏移超出文件长度，文件可能已截断或被篡改。');
    if (eocd.cdSize > MAX_CENTRAL_DIRECTORY) throw new Error('ZIP 中央目录超过 64 MiB，已停止解析。');
    const limit = options.maxEntries || MAX_ENTRIES;
    const directory = await readRange(source, eocd.cdOffset, eocd.cdSize);
    const entries = [];
    let offset = 0;
    let truncated = false;
    while (offset + 46 <= directory.length) {
      if (readU32(directory, offset) !== 0x02014b50) break;
      const flags = readU16(directory, offset + 8);
      const method = readU16(directory, offset + 10);
      const dosTime = readU16(directory, offset + 12);
      const dosDate = readU16(directory, offset + 14);
      const crc32 = readU32(directory, offset + 16);
      const compressedSize32 = readU32(directory, offset + 20);
      const size32 = readU32(directory, offset + 24);
      const nameLength = readU16(directory, offset + 28);
      const extraLength = readU16(directory, offset + 30);
      const commentLength = readU16(directory, offset + 32);
      const diskStart = readU16(directory, offset + 34);
      const internalAttributes = readU16(directory, offset + 36);
      const externalAttributes = readU32(directory, offset + 38);
      const localHeaderOffset = readU32(directory, offset + 42);
      const recordEnd = offset + 46 + nameLength + extraLength + commentLength;
      if (recordEnd > directory.length) { truncated = true; break; }
      if (entries.length >= limit) { truncated = true; break; }
      const nameBytes = directory.subarray(offset + 46, offset + 46 + nameLength);
      const extraBytes = directory.subarray(offset + 46 + nameLength, offset + 46 + nameLength + extraLength);
      const commentBytes = directory.subarray(offset + 46 + nameLength + extraLength, recordEnd);
      const extra = parseExtraFields(extraBytes);
      const entry = {
        index: entries.length,
        name: decodeZipName(nameBytes, flags, extra),
        nameBytes,
        flags,
        method,
        crc32,
        compressedSize: compressedSize32,
        size: size32,
        localHeaderOffset,
        diskStart,
        internalAttributes,
        externalAttributes,
        comment: commentBytes.length ? utf8(commentBytes) : '',
        extra,
        utf8Name: Boolean(flags & 0x800),
        encrypted: Boolean(flags & 1),
        dataDescriptor: Boolean(flags & 8)
      };
      if (compressedSize32 === 0xffffffff || size32 === 0xffffffff || localHeaderOffset === 0xffffffff || diskStart === 0xffff) {
        zip64Values(entry, extra, ['size', 'compressedSize', 'localHeaderOffset', 'diskStart']);
      }
      const dos = dosDateTime(dosDate, dosTime);
      entry.dosTime = dos.text;
      entry.dosUnix = dos.unix;
      entry.extendedTime = extendedTimestamp(extra);
      entry.isDirectory = entry.name.endsWith('/');
      entries.push(entry);
      offset = recordEnd;
    }
    return {
      entries,
      comment: utf8(eocd.comment),
      commentBytes: eocd.comment.length,
      entryCount: eocd.entryCount,
      cdOffset: eocd.cdOffset,
      cdSize: eocd.cdSize,
      eocdOffset: eocd.eocdOffset,
      zip64: eocd.zip64,
      truncated
    };
  }

  async function readEntry(source, entry, options = {}) {
    const maxSize = options.maxSize || 64 * 1024 * 1024;
    if (entry.isDirectory) return new Uint8Array(0);
    if (entry.encrypted) throw new Error('条目已加密，无法读取：' + entry.name);
    if (entry.size > maxSize) throw new Error('条目解压后超过 ' + formatBytes(maxSize) + ' 限制：' + entry.name);
    if (entry.localHeaderOffset + 30 > source.size) throw new Error('条目本地头偏移无效：' + entry.name);
    const header = await readRange(source, entry.localHeaderOffset, 30);
    if (readU32(header, 0) !== 0x04034b50) throw new Error('条目本地头签名无效：' + entry.name);
    const nameLength = readU16(header, 26);
    const extraLength = readU16(header, 28);
    const dataOffset = entry.localHeaderOffset + 30 + nameLength + extraLength;
    if (dataOffset + entry.compressedSize > source.size) throw new Error('条目数据超出文件长度：' + entry.name);
    const compressed = await readRange(source, dataOffset, entry.compressedSize);
    if (entry.method === 0) {
      if (compressed.length !== entry.size) throw new Error('存储条目长度与中央目录不一致：' + entry.name);
      return compressed;
    }
    if (entry.method === 8) {
      if (typeof options.inflate === 'function') return options.inflate(compressed, entry.size);
      if (typeof DecompressionStream !== 'function') throw new Error('当前环境不支持 deflate 解压。');
      const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
      const buffer = await new Response(stream).arrayBuffer();
      const result = new Uint8Array(buffer);
      if (result.length !== entry.size) throw new Error('解压长度与中央目录不一致：' + entry.name);
      return result;
    }
    throw new Error('不支持的 ZIP 压缩方法 ' + entry.method + '：' + entry.name);
  }

  async function readEntryPrefix(source, entry, length) {
    if (entry.isDirectory) return new Uint8Array(0);
    if (entry.encrypted) throw new Error('条目已加密，无法读取：' + entry.name);
    if (entry.method === 0) {
      if (entry.localHeaderOffset + 30 > source.size) throw new Error('条目本地头偏移无效：' + entry.name);
      const header = await readRange(source, entry.localHeaderOffset, 30);
      if (readU32(header, 0) !== 0x04034b50) throw new Error('条目本地头签名无效：' + entry.name);
      const dataOffset = entry.localHeaderOffset + 30 + readU16(header, 26) + readU16(header, 28);
      const take = Math.min(length, entry.compressedSize, source.size - dataOffset);
      return readRange(source, dataOffset, Math.max(0, take));
    }
    if (entry.size > 64 * 1024 * 1024) throw new Error('条目不支持读取前缀：' + entry.name);
    const bytes = await readEntry(source, entry, { maxSize: Math.max(entry.size, length) });
    return bytes.subarray(0, Math.min(length, bytes.length));
  }

  Object.assign(Api, {
    version: 1,
    util: {
      readU16, readU32, readU64, writeU32, hex, utf8, isPrintableText, cstring, adler32,
      formatBytes, readRange, checkSource, sourceFromBytes, MAX_FILE_SIZE
    },
    hash: hashApi,
    zip: { readDirectory, readEntry, readEntryPrefix, parseExtraFields }
  });
  if (typeof module === 'object' && module.exports) module.exports = Api;
})();
