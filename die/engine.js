/*
 * SimplerForensics — browser port of the Detect It Easy (DiE-JS) signature
 * runner for PE files.
 *
 * The module parses PE32/PE32+ files, exposes the subset of the DiE-JS PE API
 * used by the official db/PE signatures, then executes those signatures in a
 * restricted function scope and collects their results.
 *
 * It is a static analyser: the sample is never executed, written or uploaded.
 * Signatures that need the native disassembler / .NET metadata engine are
 * reported as skipped instead of being silently ignored.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.DIEEngine = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const MAX_SECTIONS = 96;
  const MAX_IMPORTS = 4096;
  const MAX_EXPORTS = 4096;
  const MAX_RESOURCES = 4096;
  const MAX_SIGNATURE_STEPS = 4096;

  const TEXT = new TextDecoder("utf-8", { fatal: false });
  const utf16 = new TextDecoder("utf-16le", { fatal: false });

  const hex2 = value => value.toString(16).padStart(2, "0").toUpperCase();
  const toHex = (bytes, start, length) => {
    let out = "";
    for (let i = 0; i < length; i++) out += hex2(bytes[start + i]);
    return out;
  };
  const align = (value, boundary) => (value + boundary - 1) & ~(boundary - 1);
  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

  function readCString(bytes, offset, limit) {
    if (offset < 0 || offset >= bytes.length) return "";
    let end = offset;
    const max = Math.min(bytes.length, offset + (limit || 4096));
    while (end < max && bytes[end] !== 0) end++;
    return TEXT.decode(bytes.subarray(offset, end));
  }

  function readWideString(bytes, offset, limit) {
    if (offset < 0 || offset + 1 >= bytes.length) return "";
    let end = offset;
    const max = Math.min(bytes.length - 1, offset + (limit || 4096));
    while (end < max && (bytes[end] !== 0 || bytes[end + 1] !== 0)) end += 2;
    return utf16.decode(bytes.subarray(offset, end));
  }

  function entropyOf(bytes, start, length) {
    if (!length) return 0;
    const counts = new Uint32Array(256);
    const end = start + length;
    for (let i = start; i < end; i++) counts[bytes[i]]++;
    let result = 0;
    for (let i = 0; i < 256; i++) {
      if (!counts[i]) continue;
      const p = counts[i] / length;
      result -= p * Math.log2(p);
    }
    return Math.round(result * 100) / 100;
  }

  // CRC-32C (Castagnoli) with a zero initial value and final inversion, matching
  // XBinary::getStringCustomCRC32 used by PE.getImportHash32().
  const CRC_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let crc = i;
      for (let k = 0; k < 8; k++) crc = crc & 1 ? (crc >>> 1) ^ 0x82f63b78 : crc >>> 1;
      table[i] = crc >>> 0;
    }
    return table;
  })();

  function customCRC32(text) {
    const bytes = new TextEncoder().encode(text);
    let crc = 0;
    for (let i = 0; i < bytes.length; i++) {
      crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ bytes[i]) & 0xff];
    }
    return (~crc) >>> 0;
  }

  function indexOfBytes(haystack, needle, from, end) {
    if (!needle.length) return from;
    const last = Math.min(end, haystack.length) - needle.length;
    const first = needle[0];
    let i = Math.max(0, from);
    while (i <= last) {
      i = haystack.indexOf(first, i);
      if (i === -1 || i > last) return -1;
      let ok = true;
      for (let j = 1; j < needle.length; j++) {
        if (haystack[i + j] !== needle[j]) { ok = false; break; }
      }
      if (ok) return i;
      i++;
    }
    return -1;
  }

  /* ------------------------------------------------------------------ *
   *  Signature grammar (XBinary::convertSignature / getSignatureRecords)
   * ------------------------------------------------------------------ */

  // Token kinds. COMPARE/SKIP/NOTNULL/ANSI/NOTANSI/NOTANSIANDNULL/ANSINUMBER/
  // FINDBYTES/RELOFFSET/ADDRESS mirror the C++ ST_* records.
  const T = {
    COMPARE: 1, SKIP: 2, NOTNULL: 3, ANSI: 4, NOTANSI: 5, NOTANSIANDNULL: 6,
    ANSINUMBER: 7, FINDBYTES: 8, RELOFFSET: 9, ADDRESS: 10
  };

  function convertSignature(signature) {
    let out = "";
    let quoted = false;
    for (let i = 0; i < signature.length; i++) {
      const ch = signature[i];
      if (ch === "'") { quoted = !quoted; continue; }
      if (quoted) {
        const code = ch.codePointAt(0);
        if (code > 0xff) return null;
        out += code.toString(16).padStart(2, "0");
      } else if (!/\s/.test(ch)) {
        out += ch === "?" ? "." : ch.toLowerCase();
      }
    }
    return quoted ? null : out;
  }

  function compileSignature(signature) {
    const normalized = convertSignature(String(signature || ""));
    if (!normalized) return null;
    const tokens = [];
    const n = normalized.length;
    let i = 0;

    const readRun = (char) => {
      let count = 0;
      while (i < n && normalized[i] === char) { count++; i++; }
      return count;
    };

    while (i < n) {
      const ch = normalized[i];
      if (ch === ".") {
        const count = readRun(".");
        if (!count || count % 2) return null;
        tokens.push({ kind: T.SKIP, size: count / 2 });
      } else if (ch === "*") {
        const count = readRun("*");
        if (!count || count % 2) return null;
        tokens.push({ kind: T.NOTNULL, size: count / 2 });
      } else if (ch === "%") {
        const pair = normalized.slice(i, i + 2);
        let kind;
        if (pair === "%%") kind = T.ANSI;
        else if (pair === "%&") kind = T.ANSINUMBER;
        else return null;
        let count = 0;
        while (normalized.slice(i, i + 2) === pair) { count++; i += 2; }
        tokens.push({ kind, size: count });
      } else if (ch === "!") {
        if (normalized.slice(i, i + 2) !== "!%") return null;
        let count = 0;
        while (normalized.slice(i, i + 2) === "!%") { count++; i += 2; }
        tokens.push({ kind: T.NOTANSI, size: count });
      } else if (ch === "_") {
        if (normalized.slice(i, i + 2) !== "_%") return null;
        let count = 0;
        while (normalized.slice(i, i + 2) === "_%") { count++; i += 2; }
        tokens.push({ kind: T.NOTANSIANDNULL, size: count });
      } else if (ch === "+") {
        const count = readRun("+");
        let start = i;
        while (i < n && /[0-9a-fA-F]/.test(normalized[i])) i++;
        const hex = normalized.slice(start, i);
        if (!hex || hex.length % 2) return null;
        const data = new Uint8Array(hex.length / 2);
        for (let j = 0; j < data.length; j++) data[j] = parseInt(hex.slice(j * 2, j * 2 + 2), 16);
        tokens.push({ kind: T.FINDBYTES, data, delta: 32 * count });
      } else if (ch === "$") {
        const count = readRun("$");
        const size = count / 2;
        if (!count || count % 2 || ![1, 2, 4, 8].includes(size)) return null;
        tokens.push({ kind: T.RELOFFSET, size });
      } else if (ch === "#") {
        const count = readRun("#");
        if (!count || count % 2) return null;
        let base = 0;
        if (normalized[i] === "[") {
          const close = normalized.indexOf("]", i);
          if (close < 0) return null;
          const baseText = normalized.slice(i + 1, close);
          if (!/^[0-9a-f]+$/.test(baseText)) return null;
          base = parseInt(baseText, 16);
          i = close + 1;
        }
        const size = count / 2;
        if (![1, 2, 4, 8].includes(size)) return null;
        tokens.push({ kind: T.ADDRESS, size, base });
      } else if (/[0-9a-fA-F]/.test(ch)) {
        const start = i;
        while (i < n && /[0-9a-fA-F]/.test(normalized[i])) i++;
        const hex = normalized.slice(start, i);
        if (hex.length % 2) return null;
        const data = new Uint8Array(hex.length / 2);
        for (let j = 0; j < data.length; j++) data[j] = parseInt(hex.slice(j * 2, j * 2 + 2), 16);
        tokens.push({ kind: T.COMPARE, data });
      } else {
        return null;
      }
    }

    if (!tokens.length) return null;
    let fixed = 0;
    for (const token of tokens) {
      if (token.kind === T.COMPARE) fixed += token.data.length;
      else if (token.kind === T.FINDBYTES) fixed += token.data.length;
      else if (token.kind === T.RELOFFSET || token.kind === T.ADDRESS) fixed += token.size;
      else fixed += token.size;
    }
    return { tokens, minLength: fixed };
  }

  function matchesAt(context, tokens, start) {
    const bytes = context.bytes;
    const size = bytes.length;
    let offset = start;
    if (!Number.isFinite(offset) || offset < 0 || offset > size) return false;

    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      switch (token.kind) {
        case T.COMPARE: {
          const data = token.data;
          if (offset > size - data.length) return false;
          for (let j = 0; j < data.length; j++) if (bytes[offset + j] !== data[j]) return false;
          offset += data.length;
          break;
        }
        case T.SKIP:
          if (offset > size - token.size) return false;
          offset += token.size;
          break;
        case T.NOTNULL:
          if (offset > size - token.size) return false;
          for (let j = 0; j < token.size; j++) if (bytes[offset + j] === 0) return false;
          offset += token.size;
          break;
        case T.ANSI:
          if (offset > size - token.size) return false;
          for (let j = 0; j < token.size; j++) {
            const b = bytes[offset + j];
            if (b < 0x20 || b >= 0x80) return false;
          }
          offset += token.size;
          break;
        case T.NOTANSI:
          if (offset > size - token.size) return false;
          for (let j = 0; j < token.size; j++) {
            const b = bytes[offset + j];
            if (b >= 0x20 && b < 0x80) return false;
          }
          offset += token.size;
          break;
        case T.NOTANSIANDNULL:
          if (offset > size - token.size) return false;
          for (let j = 0; j < token.size; j++) {
            const b = bytes[offset + j];
            if (b === 0 || (b >= 0x20 && b < 0x80)) return false;
          }
          offset += token.size;
          break;
        case T.ANSINUMBER:
          if (offset > size - token.size) return false;
          for (let j = 0; j < token.size; j++) {
            const b = bytes[offset + j];
            if (b < 0x30 || b > 0x39) return false;
          }
          offset += token.size;
          break;
        case T.FINDBYTES: {
          if (offset > size - token.data.length) return false;
          const end = Math.min(size, offset + token.delta + token.data.length);
          const found = indexOfBytes(bytes, token.data, offset, end);
          if (found < 0) return false;
          offset = found + token.data.length;
          break;
        }
        case T.RELOFFSET: {
          if (offset > size - token.size) return false;
          // DiE resolves relative offsets against the next instruction:
          // 1-byte jumps add 1, 2/4/8-byte fields add their own width.
          let delta;
          if (token.size === 1) delta = 1 + (bytes[offset] << 24 >> 24);
          else if (token.size === 2) delta = 2 + (((bytes[offset] | (bytes[offset + 1] << 8)) << 16) >> 16);
          else if (token.size === 4) {
            delta = 4 + (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24));
          } else {
            let value = 0;
            for (let j = 7; j >= 0; j--) value = value * 256 + bytes[offset + j];
            if (value > 0x7fffffffffffffff) value -= 0x10000000000000000;
            delta = 8 + value;
          }
          const address = context.offsetToAddress(offset);
          if (address < 0) return false;
          const target = context.addressToOffset(address + delta);
          if (target < 0) return false;
          offset = target;
          break;
        }
        case T.ADDRESS: {
          if (offset > size - token.size) return false;
          let value = 0;
          for (let j = token.size - 1; j >= 0; j--) value = value * 256 + bytes[offset + j];
          const target = context.addressToOffset(value + token.base);
          if (target < 0) return false;
          offset = target;
          break;
        }
        default:
          return false;
      }
      if (offset < 0 || offset > size) return false;
    }
    return true;
  }

  function findInRange(context, compiled, start, length, budget) {
    const bytes = context.bytes;
    const from = Math.max(0, start);
    const to = Math.min(bytes.length, start + Math.max(0, length));
    const last = to - compiled.minLength;
    if (last < from) return -1;

    const first = compiled.tokens.find(token => token.kind === T.COMPARE);
    if (first && compiled.tokens[0] === first) {
      const needle = first.data;
      let position = from;
      while (position <= last) {
        if (budget && budget.expired()) throw ABORT;
        position = indexOfBytes(bytes, needle, position, last + needle.length);
        if (position < 0) return -1;
        if (matchesAt(context, compiled.tokens, position)) return position;
        position++;
      }
      return -1;
    }

    for (let position = from; position <= last; position++) {
      if (budget && (position & 0x3fff) === 0 && budget.expired()) throw ABORT;
      if (matchesAt(context, compiled.tokens, position)) return position;
    }
    return -1;
  }

  const ABORT = { aborted: true };

  /* ------------------------------------------------------------------ *
   *  PE parser
   * ------------------------------------------------------------------ */

  function parsePE(bytes, fileName) {
    const pe = {
      valid: false,
      reason: "",
      bytes,
      size: bytes.length,
      fileName: fileName || "",
      sections: [],
      imports: [],
      exports: [],
      resources: [],
      warnings: [],
      versionInfo: null,
      manifest: "",
      pdb: "",
      rich: null,
      debugRecords: [],
      isNet: false,
      net: null,
      overlayOffset: bytes.length,
      overlaySize: 0,
      security: null,
      tls: false,
      signatureCache: new Map()
    };

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const u8 = offset => (offset >= 0 && offset < bytes.length ? bytes[offset] : 0);
    const u16 = offset => (offset >= 0 && offset + 2 <= bytes.length ? view.getUint16(offset, true) : 0);
    const u32 = offset => (offset >= 0 && offset + 4 <= bytes.length ? view.getUint32(offset, true) : 0);
    const i32 = offset => (offset >= 0 && offset + 4 <= bytes.length ? view.getInt32(offset, true) : 0);

    if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) {
      pe.reason = "文件不含 MZ DOS 头，无法按 PE 解析。";
      return pe;
    }

    const peOffset = u32(0x3c);
    if (peOffset < 0x40 || peOffset + 24 > bytes.length || u32(peOffset) !== 0x00004550) {
      pe.reason = "未找到有效的 PE 签名（MZ 头存在，但 e_lfanew/PE 头无效）。";
      return pe;
    }

    const coff = peOffset + 4;
    const optional = coff + 20;
    const optSize = u16(coff + 16);
    const magic = u16(optional);
    const is64 = magic === 0x20b;
    if (!is64 && magic !== 0x10b) {
      pe.reason = "Optional Header Magic 不是 PE32/PE32+。";
      return pe;
    }
    if (optional + optSize > bytes.length || optSize < 96) {
      pe.reason = "Optional Header 不完整或超出文件范围。";
      return pe;
    }

    pe.valid = true;
    pe.peOffset = peOffset;
    pe.machine = u16(coff);
    pe.machineName = ({
      0x014c: "x86 (i386)", 0x8664: "x64 (AMD64)", 0x01c0: "ARM", 0x01c4: "ARMv7 (Thumb-2)",
      0xaa64: "ARM64", 0x0200: "IA-64", 0x01c2: "ARM (Thumb)", 0x0ebc: "EFI Byte Code"
    })[pe.machine] || `未知 (0x${pe.machine.toString(16).toUpperCase()})`;
    pe.numberOfSections = u16(coff + 2);
    pe.timestamp = u32(coff + 4);
    pe.characteristics = u16(coff + 18);
    pe.optionalSize = optSize;
    pe.is64 = is64;
    pe.linkerMajor = u8(optional + 2);
    pe.linkerMinor = u8(optional + 3);
    pe.sizeOfCode = u32(optional + 4);
    pe.sizeOfInitializedData = u32(optional + 8);
    pe.sizeOfUninitializedData = u32(optional + 12);
    pe.entryRva = u32(optional + 16);
    pe.baseOfCode = u32(optional + 20);
    pe.imageBase = is64 ? Number(view.getBigUint64(optional + 24, true)) : u32(optional + 28);
    pe.sectionAlignment = u32(optional + 32);
    pe.fileAlignment = u32(optional + 36);
    pe.osVersion = `${u16(optional + 40)}.${u16(optional + 42)}`;
    pe.subsystemVersion = `${u16(optional + 48)}.${u16(optional + 50)}`;
    pe.sizeOfImage = u32(optional + 56);
    pe.sizeOfHeaders = u32(optional + 60);
    pe.checksum = u32(optional + 64);
    pe.subsystem = u16(optional + 68);
    pe.subsystemName = ({ 1: "NATIVE (驱动)", 2: "WINDOWS GUI", 3: "WINDOWS CUI", 5: "OS/2 CUI", 7: "POSIX CUI", 9: "WINDOWS CE", 10: "EFI 应用", 11: "EFI 驱动", 12: "EFI ROM", 14: "XBOX" })[pe.subsystem] || `未知 (${pe.subsystem})`;
    pe.dllCharacteristics = u16(optional + 70);
    pe.numberOfRvaAndSizes = u32(optional + (is64 ? 108 : 92));
    pe.isDll = !!(pe.characteristics & 0x2000);
    pe.isDriver = pe.subsystem === 1;
    pe.isConsole = pe.subsystem === 3;

    const dirBase = optional + (is64 ? 112 : 96);
    const dirCount = Math.min(pe.numberOfRvaAndSizes, 16);
    pe.directories = [];
    for (let i = 0; i < dirCount; i++) {
      const at = dirBase + i * 8;
      if (at + 8 > optional + optSize) break;
      pe.directories.push({ rva: u32(at), size: u32(at + 4) });
    }
    const dir = index => pe.directories[index] || { rva: 0, size: 0 };

    const sectionsAt = optional + optSize;
    const sectionCount = Math.min(pe.numberOfSections, MAX_SECTIONS);
    for (let i = 0; i < sectionCount; i++) {
      const at = sectionsAt + i * 40;
      if (at + 40 > bytes.length) { pe.warnings.push("节表被文件尾截断。"); break; }
      const name = TEXT.decode(bytes.subarray(at, at + 8)).replace(/\0.*$/, "").trim();
      const virtualSize = u32(at + 8);
      const virtualAddress = u32(at + 12);
      const rawSize = u32(at + 16);
      const rawPointer = u32(at + 20);
      const characteristics = u32(at + 36);
      const rawEnd = rawPointer + rawSize;
      pe.sections.push({
        index: i, name, virtualSize, virtualAddress, rawSize, rawPointer, characteristics,
        readable: !!(characteristics & 0x40000000),
        writable: !!(characteristics & 0x80000000),
        executable: !!(characteristics & 0x20000000),
        flagsText: (characteristics & 0x40000000 ? "R" : "-") + (characteristics & 0x80000000 ? "W" : "-") + (characteristics & 0x20000000 ? "X" : "-"),
        entropy: entropyOf(bytes, rawPointer, Math.min(rawSize, Math.max(0, bytes.length - rawPointer))),
        rawEnd,
        rangeValid: rawPointer + rawSize <= bytes.length
      });
      if (!pe.sections[i].rangeValid) pe.warnings.push(`节区 ${name} 的原始数据超出文件范围。`);
    }

    function rvaToOffset(rva) {
      if (!rva) return -1;
      if (rva < pe.sizeOfHeaders && rva < bytes.length) return rva;
      for (const section of pe.sections) {
        const end = section.virtualAddress + Math.max(section.virtualSize, section.rawSize);
        if (rva >= section.virtualAddress && rva < end) {
          const delta = rva - section.virtualAddress;
          if (delta >= section.rawSize) return -1;
          const offset = section.rawPointer + delta;
          return offset < bytes.length ? offset : -1;
        }
      }
      return -1;
    }

    pe.rvaToOffset = rvaToOffset;
    pe.vaToOffset = va => {
      const rva = va - pe.imageBase;
      return rva >= 0 ? rvaToOffset(rva) : -1;
    };
    pe.offsetToRva = offset => {
      if (offset < 0) return -1;
      if (offset < pe.sizeOfHeaders) return offset;
      for (const section of pe.sections) {
        if (offset >= section.rawPointer && offset < section.rawPointer + section.rawSize) {
          return section.virtualAddress + (offset - section.rawPointer);
        }
      }
      return -1;
    };
    pe.offsetToAddress = offset => {
      const rva = pe.offsetToRva(offset);
      return rva < 0 ? -1 : pe.imageBase + rva;
    };
    pe.addressToOffset = address => {
      const rva = address - pe.imageBase;
      return rva >= 0 && rva <= 0xffffffff ? rvaToOffset(rva) : -1;
    };

    // Entry point / overlay
    pe.entryOffset = rvaToOffset(pe.entryRva);
    let rawEnd = Math.min(bytes.length, pe.sizeOfHeaders);
    for (const section of pe.sections) rawEnd = Math.max(rawEnd, Math.min(bytes.length, section.rawEnd));
    pe.overlayOffset = rawEnd;
    pe.overlaySize = Math.max(0, bytes.length - rawEnd);
    pe.entrySection = -1;
    for (const section of pe.sections) {
      const size = Math.max(section.virtualSize, section.rawSize);
      if (pe.entryRva >= section.virtualAddress && pe.entryRva < section.virtualAddress + size) {
        pe.entrySection = section.index;
        break;
      }
    }
    if (pe.entryOffset < 0) pe.warnings.push("入口点 RVA 无法映射到文件偏移。");
    else {
      const entrySection = pe.sections[pe.entrySection];
      if (entrySection && !entrySection.executable) pe.warnings.push("入口点位于不可执行节区。");
    }
    if (pe.overlaySize > 0) pe.warnings.push(`文件尾部存在 ${pe.overlaySize.toLocaleString("en-US")} 字节附加数据（overlay）。`);

    // Imports
    const importDirectory = dir(1);
    if (importDirectory.rva) {
      let descriptor = rvaToOffset(importDirectory.rva);
      let guard = 0;
      while (descriptor >= 0 && descriptor + 20 <= bytes.length && guard++ < 512) {
        const originalFirstThunk = u32(descriptor);
        const nameRva = u32(descriptor + 12);
        const firstThunk = u32(descriptor + 16);
        if (!originalFirstThunk && !nameRva && !firstThunk) break;
        const nameOffset = rvaToOffset(nameRva);
        const library = nameOffset >= 0 ? readCString(bytes, nameOffset, 512) : "";
        const thunkRva = originalFirstThunk || firstThunk;
        const thunkOffset = rvaToOffset(thunkRva);
        const functions = [];
        if (thunkOffset >= 0) {
          const step = is64 ? 8 : 4;
          const ordinalMask = is64 ? 0x8000000000000000n : 0x80000000n;
          for (let i = 0; i < 4096 && thunkOffset + (i + 1) * step <= bytes.length; i++) {
            const value = is64 ? view.getBigUint64(thunkOffset + i * step, true) : BigInt(u32(thunkOffset + i * step));
            if (value === 0n) break;
            if (value & ordinalMask) {
              functions.push({ name: "", ordinal: Number(value & 0xffffn) });
            } else {
              const hintOffset = rvaToOffset(Number(value));
              functions.push({ name: hintOffset >= 0 ? readCString(bytes, hintOffset + 2, 512) : "", ordinal: null });
            }
          }
        }
        if (library) pe.imports.push({ name: library, functions });
        if (pe.imports.length >= MAX_IMPORTS) { pe.warnings.push("导入表超过解析上限，仅保留前 4096 个 DLL。"); break; }
        descriptor += 20;
      }
    }

    pe.importHash32 = customCRC32(pe.imports.map(lib => lib.name + lib.functions.map(fn => fn.name || `ordinal${fn.ordinal}`).join("")).join(""));
    pe.importPositionHashes = pe.imports.map(lib => customCRC32(lib.functions.map(fn => fn.name || `ordinal${fn.ordinal}`).join("")));

    // Exports
    const exportDirectory = dir(0);
    if (exportDirectory.rva) {
      const offset = rvaToOffset(exportDirectory.rva);
      if (offset >= 0 && offset + 40 <= bytes.length) {
        const moduleRva = u32(offset + 12);
        const base = u32(offset + 16);
        const numberOfFunctions = Math.min(u32(offset + 20), MAX_EXPORTS);
        const numberOfNames = Math.min(u32(offset + 24), MAX_EXPORTS);
        const functionsOffset = rvaToOffset(u32(offset + 28));
        const namesOffset = rvaToOffset(u32(offset + 32));
        const ordinalsOffset = rvaToOffset(u32(offset + 36));
        pe.exportModule = moduleRva ? readCString(bytes, rvaToOffset(moduleRva) || 0, 512) : "";
        pe.exportBase = base;
        for (let i = 0; i < numberOfFunctions; i++) {
          const rva = functionsOffset >= 0 ? u32(functionsOffset + i * 4) : 0;
          pe.exports.push({ index: i, ordinal: base + i, rva, name: "" });
        }
        for (let i = 0; i < numberOfNames; i++) {
          if (namesOffset < 0 || ordinalsOffset < 0) break;
          const nameRva = u32(namesOffset + i * 4);
          const slot = u16(ordinalsOffset + i * 2);
          const target = pe.exports[slot];
          if (target) target.name = readCString(bytes, rvaToOffset(nameRva) || 0, 512);
        }
      }
    }

    // Resources
    const resourceDirectory = dir(2);
    if (resourceDirectory.rva) {
      const root = rvaToOffset(resourceDirectory.rva);
      if (root >= 0) {
        const entries = [];
        const readName = (base, value) => {
          if (!(value & 0x80000000)) return "";
          const nameOffset = root + (value & 0x7fffffff);
          if (nameOffset + 2 > bytes.length) return "";
          const length = u16(nameOffset);
          return utf16.decode(bytes.subarray(nameOffset + 2, Math.min(bytes.length, nameOffset + 2 + length * 2)));
        };
        const walk = (directoryOffset, level, type, nameId, nameText, typeName, language) => {
          if (entries.length >= MAX_RESOURCES || level > 2) return;
          const count = Math.min(u16(directoryOffset + 12) + u16(directoryOffset + 14), 1024);
          for (let i = 0; i < count; i++) {
            const entryOffset = directoryOffset + 16 + i * 8;
            if (entryOffset + 8 > bytes.length) return;
            const nameValue = u32(entryOffset);
            const dataValue = u32(entryOffset + 4);
            const entryName = readName(root, nameValue);
            const id = nameValue & 0x80000000 ? 0 : nameValue;
            const nextType = level === 0 ? id : type;
            const nextNameId = level === 1 ? id : nameId;
            const nextNameText = level === 1 ? (entryName || nameText) : nameText;
            const nextTypeName = level === 0 ? (entryName || typeName) : typeName;
            if (dataValue & 0x80000000) {
              walk(root + (dataValue & 0x7fffffff), level + 1, nextType, nextNameId, nextNameText, nextTypeName, language);
            } else {
              const dataEntry = root + dataValue;
              if (dataEntry + 16 > bytes.length) continue;
              const dataRva = u32(dataEntry);
              const dataSize = u32(dataEntry + 4);
              const dataOffset = rvaToOffset(dataRva);
              if (dataOffset < 0) continue;
              entries.push({
                type: nextType,
                typeName: nextTypeName,
                nameId: nextNameId,
                name: nextNameText || (level >= 2 ? readName(root, nameValue) : ""),
                language: level === 2 ? id : (language || 0),
                offset: dataOffset,
                size: Math.min(dataSize, bytes.length - dataOffset)
              });
            }
          }
        };
        walk(root, 0, 0, 0, "", "", 0);
        pe.resources = entries;
      }
    }

    // Version information and manifest
    const versionResources = pe.resources.filter(resource => resource.type === 16);
    if (versionResources.length) {
      pe.versionInfo = parseVersionInfo(bytes, versionResources[0].offset, versionResources[0].size);
      pe.versionInfoResource = versionResources[0];
    }
    const manifestResource = pe.resources.find(resource => resource.type === 24);
    if (manifestResource) {
      const raw = bytes.subarray(manifestResource.offset, manifestResource.offset + manifestResource.size);
      pe.manifest = decodeTextResource(raw).trim();
    }

    // Debug directory / PDB
    const debugDirectory = dir(6);
    if (debugDirectory.rva && debugDirectory.size) {
      const debugOffset = rvaToOffset(debugDirectory.rva);
      const count = Math.min(Math.floor(debugDirectory.size / 28), 64);
      for (let i = 0; i < count; i++) {
        const at = debugOffset + i * 28;
        if (at < 0 || at + 28 > bytes.length) break;
        const type = u32(at + 12);
        const dataSize = u32(at + 16);
        const dataOffset = rvaToOffset(u32(at + 20));
        const record = { type, size: dataSize, offset: dataOffset };
        pe.debugRecords.push(record);
        if (dataOffset >= 0 && dataOffset + 24 <= bytes.length) {
          const magic = TEXT.decode(bytes.subarray(dataOffset, dataOffset + 4));
          if (type === 2 && (magic === "RSDS" || magic === "NB10")) {
            const pathOffset = dataOffset + (magic === "RSDS" ? 24 : 16);
            const path = readCString(bytes, pathOffset, 1024);
            if (path) pe.pdb = path;
          }
        }
      }
    }

    // Authenticode presence (structure only, no chain validation)
    const securityDirectory = dir(4);
    if (securityDirectory.rva && securityDirectory.size && securityDirectory.rva + securityDirectory.size <= bytes.length) {
      pe.security = { offset: securityDirectory.rva, size: securityDirectory.size, valid: true };
    }

    // TLS directory presence
    pe.tls = !!(dir(9).rva && dir(9).size);

    // Rich header
    pe.rich = parseRichHeader(bytes, view, peOffset);

    // .NET / CLI metadata
    pe.net = parseDotNet(bytes, pe, view, u16, u32, rvaToOffset);
    pe.isNet = !!(pe.net && pe.net.valid);
    if (pe.isNet) pe.netVersion = pe.net.version;

    if (pe.entryOffset >= 0) pe.entryBytes = toHex(bytes, pe.entryOffset, Math.min(16, bytes.length - pe.entryOffset));

    pe.api = createAPI(pe);
    return pe;
  }

  function decodeTextResource(raw) {
    if (raw.length >= 2 && raw[0] === 0xff && raw[1] === 0xfe) return utf16.decode(raw.subarray(2));
    if (raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) return TEXT.decode(raw.subarray(3));
    return TEXT.decode(raw);
  }

  function parseVersionInfo(bytes, offset, size) {
    const info = { strings: {}, fixed: null };
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const u16 = at => (at + 2 <= bytes.length ? view.getUint16(at, true) : 0);

    const align = (value, boundary) => (value + boundary - 1) & ~(boundary - 1);
    const readKey = at => {
      let end = at;
      while (end + 1 < bytes.length && (bytes[end] !== 0 || bytes[end + 1] !== 0)) end += 2;
      return utf16.decode(bytes.subarray(at, end));
    };

    const visit = (at, depth, parentKey) => {
      if (depth > 6 || at + 6 > bytes.length) return;
      const length = u16(at);
      const valueLength = u16(at + 2);
      const type = u16(at + 4);
      if (!length || at + length > bytes.length) return;
      const key = readKey(at + 6);
      const keyEnd = align(at + 6 + (key.length + 1) * 2, 4);
      let valueStart = keyEnd;
      let valueEnd = keyEnd;
      if (type === 1) valueEnd = keyEnd + valueLength * 2;
      else valueEnd = keyEnd + valueLength;
      if (valueEnd > at + length) valueEnd = at + length;
      const valueText = type === 1 ? utf16.decode(bytes.subarray(valueStart, valueEnd)).replace(/\0+$/, "") : "";
      if (depth === 0) {
        if (valueLength >= 52 && valueStart + 52 <= bytes.length) {
          info.fixed = {
            signature: view.getUint32(valueStart, true),
            fileVersion: `${view.getUint16(valueStart + 8, true)}.${view.getUint16(valueStart + 10, true)}.${view.getUint16(valueStart + 12, true)}.${view.getUint16(valueStart + 14, true)}`,
            productVersion: `${view.getUint16(valueStart + 16, true)}.${view.getUint16(valueStart + 18, true)}.${view.getUint16(valueStart + 20, true)}.${view.getUint16(valueStart + 22, true)}`
          };
        }
      } else if (key && valueText && depth >= 3) {
        info.strings[key] = valueText;
      }
      let child = align(valueEnd, 4);
      while (child + 6 <= at + length) {
        const childLength = u16(child);
        if (childLength < 6) break;
        visit(child, depth + 1, key);
        child = align(child + childLength, 4);
      }
    };

    visit(offset, 0, "");
    if (!info.strings.FileVersion && info.fixed) info.strings.FileVersion = info.fixed.fileVersion;
    return info;
  }

  function parseRichHeader(bytes, view, peOffset) {
    const start = Math.max(0x40, peOffset - 4096);
    let rich = -1;
    for (let i = start; i + 8 <= peOffset; i++) {
      if (bytes[i] === 0x52 && bytes[i + 1] === 0x69 && bytes[i + 2] === 0x63 && bytes[i + 3] === 0x68) { rich = i; break; }
    }
    if (rich < 0) return null;
    const key = view.getUint32(rich + 4, true);
    let dans = -1;
    for (let i = 0x40; i + 16 <= rich; i += 4) {
      if ((view.getUint32(i, true) ^ key) >>> 0 === 0x536e6144) { dans = i; break; }
    }
    const entries = [];
    if (dans >= 0) {
      for (let i = dans + 16; i + 8 <= rich; i += 8) {
        const product = (view.getUint32(i, true) ^ key) >>> 0;
        const count = (view.getUint32(i + 4, true) ^ key) >>> 0;
        entries.push({ productId: product & 0xffff, build: product >>> 16, count });
        if (entries.length >= 64) break;
      }
    }
    return { offset: rich, key, entries, hasDanS: dans >= 0 };
  }

  function parseDotNet(bytes, pe, view, u16, u32, rvaToOffset) {
    const directory = (pe.directories || [])[14];
    if (!directory || !directory.rva || !directory.size) return null;
    const cliOffset = rvaToOffset(directory.rva);
    if (cliOffset < 0 || cliOffset + 72 > bytes.length) return null;
    const metadataRva = u32(cliOffset + 8);
    const metadataSize = u32(cliOffset + 12);
    const metadataOffset = rvaToOffset(metadataRva);
    if (metadataOffset < 0 || metadataOffset + 16 > bytes.length) return null;
    if (bytes[metadataOffset] !== 0x42 || bytes[metadataOffset + 1] !== 0x53 || bytes[metadataOffset + 2] !== 0x4a || bytes[metadataOffset + 3] !== 0x42) {
      return { valid: false, reason: "CLI 头存在，但元数据签名不是 BSJB。" };
    }
    const versionLength = u32(metadataOffset + 12);
    if (versionLength > 256) return { valid: false, reason: "元数据版本字符串长度异常。" };
    const version = TEXT.decode(bytes.subarray(metadataOffset + 16, metadataOffset + 16 + versionLength)).replace(/\0+$/, "");
    const streamCount = u16(metadataOffset + 16 + versionLength + 2);
    let cursor = metadataOffset + 16 + versionLength + 4;
    const streams = {};
    for (let i = 0; i < streamCount && i < 16; i++) {
      if (cursor + 8 > bytes.length) break;
      const offset = u32(cursor);
      const size = u32(cursor + 4);
      let nameEnd = cursor + 8;
      while (nameEnd < bytes.length && nameEnd < cursor + 8 + 32 && bytes[nameEnd] !== 0) nameEnd++;
      const name = TEXT.decode(bytes.subarray(cursor + 8, nameEnd));
      streams[name] = { offset: metadataOffset + offset, size, fileOffset: metadataOffset + offset };
      cursor = align(nameEnd + 1, 4);
    }
    const strings = streams["#Strings"];
    const us = streams["#US"];
    const blob = streams["#Blob"];
    const tables = streams["#~"] || streams["#-"];
    const net = {
      valid: true, version, streams, cliOffset,
      stringsStart: strings ? strings.offset : -1,
      stringsEnd: strings ? Math.min(bytes.length, strings.offset + strings.size) : -1,
      usStart: us ? us.offset : -1,
      usEnd: us ? Math.min(bytes.length, us.offset + us.size) : -1,
      blobStart: blob ? blob.offset : -1,
      blobEnd: blob ? Math.min(bytes.length, blob.offset + blob.size) : -1,
      tablesStart: tables ? tables.offset : -1,
      metadataSize,
      moduleName: "", assemblyName: "", typeCount: 0, methodCount: 0, types: []
    };

    if (tables && net.stringsStart >= 0) {
      try {
        parseDotNetTables(bytes, net, view, tables);
      } catch (error) {
        net.tableError = error && error.message ? error.message : String(error);
      }
    }
    return net;
  }

  // Minimal ECMA-335 metadata table reader: enough to expose Module, TypeRef,
  // TypeDef names and TypeDef/MethodDef counts without pulling in a full CLR
  // metadata implementation.
  function parseDotNetTables(bytes, net, view, tables) {
    const u16 = offset => (offset + 2 <= bytes.length ? view.getUint16(offset, true) : 0);
    const u32 = offset => (offset + 4 <= bytes.length ? view.getUint32(offset, true) : 0);
    const start = tables.offset;
    if (start + 24 > bytes.length) return;
    const heapSizes = bytes[start + 6];
    const valid = view.getBigUint64(start + 8, true);
    let cursor = start + 24;
    const rowCount = new Array(64).fill(0);
    for (let table = 0; table < 64; table++) {
      if ((valid >> BigInt(table)) & 1n) {
        rowCount[table] = u32(cursor);
        cursor += 4;
      }
    }
    const stringSize = heapSizes & 0x01 ? 4 : 2;
    const guidSize = heapSizes & 0x02 ? 4 : 2;
    const blobSize = heapSizes & 0x04 ? 4 : 2;
    const index = table => (rowCount[table] >= 0x10000 ? 4 : 2);
    const coded = (targets, bits) => (Math.max(...targets.map(table => rowCount[table])) < (1 << (16 - bits)) ? 2 : 4);
    const typeDefOrRef = () => coded([0x02, 0x01, 0x1b], 2);
    const resolutionScope = () => coded([0x00, 0x1a, 0x23, 0x01], 2);

    const rowSizes = new Array(64).fill(0);
    rowSizes[0x00] = 2 + stringSize + guidSize * 3;
    rowSizes[0x01] = resolutionScope() + stringSize * 2;
    rowSizes[0x02] = 4 + stringSize * 2 + typeDefOrRef() + index(0x04) + index(0x06);
    rowSizes[0x04] = 2 + stringSize + blobSize;
    rowSizes[0x06] = 4 + 2 + 2 + stringSize + blobSize + index(0x08);

    const tableOffset = table => {
      let offset = cursor;
      for (let i = 0; i < table; i++) offset += rowCount[i] * rowSizes[i];
      return offset;
    };
    const heapString = heapIndex => {
      const offset = net.stringsStart + heapIndex;
      if (offset < 0 || offset >= net.stringsEnd) return "";
      let end = offset;
      while (end < net.stringsEnd && bytes[end] !== 0) end++;
      return TEXT.decode(bytes.subarray(offset, end));
    };
    const readIndex = (offset, size) => (size === 4 ? u32(offset) : u16(offset));

    const moduleOffset = tableOffset(0x00);
    if (rowCount[0x00] > 0 && moduleOffset + rowSizes[0x00] <= bytes.length) {
      net.moduleName = heapString(readIndex(moduleOffset + 2, stringSize));
    }

    const typeRefOffset = tableOffset(0x01);
    const typeRefSize = rowSizes[0x01];
    if (rowCount[0x01] > 0 && typeRefSize > 0) {
      let offset = typeRefOffset;
      for (let i = 0; i < Math.min(rowCount[0x01], 4000) && offset + typeRefSize <= bytes.length; i++, offset += typeRefSize) {
        const name = heapString(readIndex(offset + resolutionScope(), stringSize));
        const namespace = heapString(readIndex(offset + resolutionScope() + stringSize, stringSize));
        if (name && net.types.length < 4000) net.types.push({ namespace, name, kind: "ref" });
      }
    }

    const typeDefOffset = tableOffset(0x02);
    const typeDefSize = rowSizes[0x02];
    net.typeCount = rowCount[0x02];
    net.methodCount = rowCount[0x06];
    if (rowCount[0x02] > 0 && typeDefSize > 0) {
      let offset = typeDefOffset;
      for (let i = 0; i < Math.min(rowCount[0x02], 4000) && offset + typeDefSize <= bytes.length; i++, offset += typeDefSize) {
        const name = heapString(readIndex(offset + 4, stringSize));
        const namespace = heapString(readIndex(offset + 4 + stringSize, stringSize));
        if (name) net.types.push({ namespace, name, kind: "def" });
      }
    }
  }

  /* ------------------------------------------------------------------ *
   *  DiE-JS PE API surface
   * ------------------------------------------------------------------ */

  function createAPI(pe) {
    const bytes = pe.bytes;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const sigCache = new Map();
    const overlayOffset = pe.overlayOffset;
    const overlaySize = pe.overlaySize;

    const getCompiled = signature => {
      if (signature && typeof signature === "object" && signature.tokens) return signature;
      const key = String(signature);
      if (sigCache.has(key)) return sigCache.get(key);
      const compiled = compileSignature(key);
      sigCache.set(key, compiled);
      return compiled;
    };

    const offsetValid = offset => Number.isFinite(offset) && offset >= 0 && offset <= bytes.length;

    const api = {
      // --- identity / basic reads ---
      getSize: () => bytes.length,
      getFileName: () => pe.fileName,
      getFileDirectory: () => "",
      getFileBaseName: () => {
        const name = pe.fileName.replace(/\\/g, "/").split("/").pop() || "";
        const dot = name.lastIndexOf(".");
        return dot > 0 ? name.slice(0, dot) : name;
      },
      getFileSuffix: () => {
        const name = pe.fileName.replace(/\\/g, "/").split("/").pop() || "";
        const dot = name.lastIndexOf(".");
        return dot >= 0 ? name.slice(dot + 1) : "";
      },
      getFileCompleteSuffix: () => {
        const name = pe.fileName.replace(/\\/g, "/").split("/").pop() || "";
        const dot = name.indexOf(".");
        return dot >= 0 ? name.slice(dot + 1) : "";
      },
      readByte: offset => (offset >= 0 && offset < bytes.length ? bytes[offset] : 0),
      read_uint8: offset => (offset >= 0 && offset < bytes.length ? bytes[offset] : 0),
      read_int8: offset => (offset >= 0 && offset < bytes.length ? (bytes[offset] << 24 >> 24) : 0),
      readWord: offset => (offset >= 0 && offset + 2 <= bytes.length ? view.getUint16(offset, true) : 0),
      read_uint16: offset => (offset >= 0 && offset + 2 <= bytes.length ? view.getUint16(offset, true) : 0),
      read_int16: offset => (offset >= 0 && offset + 2 <= bytes.length ? view.getInt16(offset, true) : 0),
      readDword: offset => (offset >= 0 && offset + 4 <= bytes.length ? view.getUint32(offset, true) : 0),
      readSDword: offset => (offset >= 0 && offset + 4 <= bytes.length ? view.getInt32(offset, true) : 0),
      read_uint32: offset => (offset >= 0 && offset + 4 <= bytes.length ? view.getUint32(offset, true) : 0),
      read_int32: offset => (offset >= 0 && offset + 4 <= bytes.length ? view.getInt32(offset, true) : 0),
      readQword: offset => (offset >= 0 && offset + 8 <= bytes.length ? Number(view.getBigUint64(offset, true)) : 0),
      read_uint64: offset => (offset >= 0 && offset + 8 <= bytes.length ? Number(view.getBigUint64(offset, true)) : 0),
      readBytes: (offset, size) => Array.from(bytes.subarray(Math.max(0, offset), Math.max(0, offset) + Math.max(0, size))),
      read_array: (offset, size) => Array.from(bytes.subarray(Math.max(0, offset), Math.max(0, offset) + Math.max(0, size))),
      getSignature: (offset, size) => {
        if (offset < 0 || offset >= bytes.length || size <= 0) return "";
        return toHex(bytes, offset, Math.min(size, bytes.length - offset));
      },
      getString: (offset, size) => {
        if (offset < 0 || offset >= bytes.length) return "";
        const limit = size === undefined ? 4096 : Math.min(size, bytes.length - offset);
        let end = offset;
        while (end < offset + limit && bytes[end] !== 0) end++;
        return TEXT.decode(bytes.subarray(offset, end));
      },
      cleanString: value => {
        if (value === null || value === undefined) return "";
        const text = Array.isArray(value) ? value.join("") : String(value);
        return text.replace(/[\u0000-\u001f\u007f]/g, "").trim();
      },

      // --- comparisons / searches ---
      compare: (signature, offset) => {
        offset = offset || 0;
        if (!offsetValid(offset)) return false;
        const compiled = getCompiled(signature);
        return !!compiled && matchesAt(api, compiled.tokens, offset);
      },
      compareEP: (signature, offset) => {
        if (pe.entryOffset < 0) return false;
        offset = offset || 0;
        const compiled = getCompiled(signature);
        return !!compiled && matchesAt(api, compiled.tokens, pe.entryOffset + offset);
      },
      compareOverlay: (signature, offset) => {
        if (overlaySize <= 0) return false;
        offset = offset || 0;
        const compiled = getCompiled(signature);
        return !!compiled && matchesAt(api, compiled.tokens, overlayOffset + offset);
      },
      isSignaturePresent: (offset, size, signature) => {
        const compiled = getCompiled(signature);
        if (!compiled) return false;
        return findInRange(api, compiled, offset, size, api.__budget) >= 0;
      },
      findSignature: (offset, size, signature) => {
        const compiled = getCompiled(signature);
        if (!compiled) return -1;
        return findInRange(api, compiled, offset, size, api.__budget);
      },
      findSignatures: (offset, size, signatures) => {
        if (!Array.isArray(signatures) || signatures.length > 128) return [];
        return signatures.map(signature => api.findSignature(offset, size, signature));
      },
      findString: (offset, size, text) => {
        const needle = new TextEncoder().encode(String(text));
        return indexOfBytes(bytes, needle, offset, offset + size);
      },
      findByte: (offset, size, value) => indexOfBytes(bytes, Uint8Array.of(value & 0xff), offset, offset + size),
      findWord: (offset, size, value) => indexOfBytes(bytes, Uint8Array.of(value & 0xff, (value >>> 8) & 0xff), offset, offset + size),
      findDword: (offset, size, value) => indexOfBytes(bytes, Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff), offset, offset + size),

      isSignatureInSectionPresent: (number, signature) => {
        const section = pe.sections[number];
        if (!section) return false;
        return api.isSignaturePresent(section.rawPointer, section.rawSize, signature);
      },
      isAnySignatureInSectionPresent: (number, signatures) => {
        if (!Array.isArray(signatures)) return false;
        return signatures.some(signature => api.isSignatureInSectionPresent(number, signature));
      },

      // --- address translation ---
      VAToOffset: va => pe.vaToOffset(va),
      RVAToOffset: rva => pe.rvaToOffset(rva),
      OffsetToVA: offset => pe.offsetToAddress(offset),
      OffsetToRVA: offset => pe.offsetToRva(offset),
      calculateEntropy: (offset, size) => entropyOf(bytes, Math.max(0, offset), Math.max(0, Math.min(size, bytes.length - offset))),

      // --- PE header ---
      getEntryPointOffset: () => pe.entryOffset,
      getEntryPointRVA: () => pe.entryRva,
      getAddressOfEntryPoint: () => pe.entryRva,
      getEntryPointSection: () => pe.entrySection,
      getImageBase: () => pe.imageBase,
      getSizeOfCode: () => pe.sizeOfCode,
      getSizeOfUninitializedData: () => pe.sizeOfUninitializedData,
      calculateSizeOfHeaders: () => pe.sizeOfHeaders,
      getMajorLinkerVersion: () => pe.linkerMajor,
      getMinorLinkerVersion: () => pe.linkerMinor,
      getOverlayOffset: () => pe.overlayOffset,
      getOverlaySize: () => pe.overlaySize,
      isOverlayPresent: () => pe.overlaySize > 0,
      getDosStubOffset: () => 0x40,
      getDosStubSize: () => Math.max(0, pe.peOffset - 0x40),
      is32: () => !pe.is64,
      is64: () => pe.is64,
      isDll: () => pe.isDll,
      isDriver: () => pe.isDriver,
      isConsole: () => pe.isConsole,
      isSignedFile: () => !!pe.security,
      isSigned: () => !!pe.security,
      isTLSPresent: () => pe.tls,
      isVerbose: () => false,
      isDeepScan: () => false,
      isHeuristicScan: () => false,
      getGeneralOptions: () => {
        const options = [];
        if (pe.dllCharacteristics & 0x40) options.push("ASLR");
        if (pe.dllCharacteristics & 0x100) options.push("DEP");
        if (pe.dllCharacteristics & 0x4000) options.push("CFG");
        if (pe.dllCharacteristics & 0x400) options.push("NoSEH");
        if (pe.security) options.push("Signed");
        return options.join(", ");
      },
      getImageOptionalHeader: name => {
        const fields = {
          Magic: pe.is64 ? 0x20b : 0x10b,
          AddressOfEntryPoint: pe.entryRva,
          ImageBase: pe.imageBase,
          SectionAlignment: pe.sectionAlignment,
          FileAlignment: pe.fileAlignment,
          SizeOfImage: pe.sizeOfImage,
          SizeOfHeaders: pe.sizeOfHeaders,
          CheckSum: pe.checksum,
          Subsystem: pe.subsystem,
          DllCharacteristics: pe.dllCharacteristics,
          MajorLinkerVersion: pe.linkerMajor,
          MinorLinkerVersion: pe.linkerMinor,
          NumberOfRvaAndSizes: pe.numberOfRvaAndSizes
        };
        return fields[name] === undefined ? 0 : fields[name];
      },
      getImageFileHeader: name => {
        const fields = {
          Machine: pe.machine,
          NumberOfSections: pe.numberOfSections,
          TimeDateStamp: pe.timestamp,
          SizeOfOptionalHeader: pe.optionalSize,
          Characteristics: pe.characteristics
        };
        return fields[name] === undefined ? 0 : fields[name];
      },

      // --- sections ---
      getNumberOfSections: () => pe.sections.length,
      getSectionName: number => (pe.sections[number] ? pe.sections[number].name : ""),
      getSectionVirtualSize: number => (pe.sections[number] ? pe.sections[number].virtualSize : 0),
      getSectionVirtualAddress: number => (pe.sections[number] ? pe.sections[number].virtualAddress : 0),
      getSectionFileSize: number => (pe.sections[number] ? pe.sections[number].rawSize : 0),
      getSectionFileOffset: number => (pe.sections[number] ? pe.sections[number].rawPointer : 0),
      getSectionCharacteristics: number => (pe.sections[number] ? pe.sections[number].characteristics : 0),
      getSectionNumber: name => pe.sections.findIndex(section => section.name === name),
      isSectionNamePresent: name => pe.sections.some(section => section.name === name),
      getImportSection: () => sectionOfDirectory(pe, 1),
      getExportSection: () => sectionOfDirectory(pe, 0),
      getResourceSection: () => sectionOfDirectory(pe, 2),
      getRelocsSection: () => sectionOfDirectory(pe, 5),
      getTLSSection: () => sectionOfDirectory(pe, 9),

      // --- imports ---
      getNumberOfImports: () => pe.imports.length,
      getImportLibraryName: number => (pe.imports[number] ? pe.imports[number].name : ""),
      getNumberOfImportThunks: number => (pe.imports[number] ? pe.imports[number].functions.length : 0),
      getImportFunctionName: (number, functionNumber) => {
        const lib = pe.imports[number];
        if (!lib || !lib.functions[functionNumber]) return "";
        const fn = lib.functions[functionNumber];
        return fn.name || (fn.ordinal !== null ? `Ordinal ${fn.ordinal}` : "");
      },
      isImportPresent: () => pe.imports.length > 0,
      isLibraryPresent: (name, checkCase) => {
        const query = checkCase ? String(name) : String(name).toLowerCase();
        return pe.imports.some(lib => (checkCase ? lib.name : lib.name.toLowerCase()) === query);
      },
      isFunctionPresent: name => {
        const query = String(name).toLowerCase();
        return pe.imports.some(library => library.functions.some(fn => (fn.name || "").toLowerCase() === query));
      },
      isLibraryFunctionPresent: (library, functionName) => {
        const lib = pe.imports.find(item => item.name.toLowerCase() === String(library).toLowerCase());
        if (!lib) return false;
        const query = String(functionName).toLowerCase();
        return lib.functions.some(fn => (fn.name || "").toLowerCase() === query);
      },
      getImportHash32: () => pe.importHash32,
      getImportPositionHashes: () => pe.importPositionHashes.slice(),
      isImportPositionHashPresent: (index, hash) => {
        const target = hash >>> 0;
        if (index === -1) return pe.importPositionHashes.some(value => value === target);
        return index >= 0 && index < pe.importPositionHashes.length && pe.importPositionHashes[index] === target;
      },

      // --- exports ---
      isExportPresent: () => pe.exports.length > 0,
      getNumberOfExportFunctions: () => pe.exports.length,
      getNumberOfExports: () => pe.exports.length,
      getExportFunctionName: number => (pe.exports[number] ? pe.exports[number].name : ""),
      getNextNamedExportFunctionIndex: previous => {
        for (let i = Math.max(-1, previous | 0) + 1; i < pe.exports.length; i++) if (pe.exports[i].name) return i;
        return -1;
      },
      getExportFunctionIndex: name => pe.exports.findIndex(item => item.name === name),

      // --- resources ---
      isResourcesPresent: () => pe.resources.length > 0,
      getNumberOfResources: () => pe.resources.length,
      getResourceIdByNumber: number => (pe.resources[number] ? pe.resources[number].nameId : 0),
      getResourceNameByNumber: number => (pe.resources[number] ? (pe.resources[number].name || pe.resources[number].typeName) : ""),
      getResourceOffsetByNumber: number => (pe.resources[number] ? pe.resources[number].offset : -1),
      getResourceSizeByNumber: number => (pe.resources[number] ? pe.resources[number].size : 0),
      getResourceTypeByNumber: number => (pe.resources[number] ? pe.resources[number].type : 0),
      isResourceNamePresent: name => pe.resources.some(resource => resource.name === name),
      isResourceGroupNamePresent: name => pe.resources.some(resource => resource.typeName === name),
      getResourceNameOffset: name => {
        const resource = pe.resources.find(item => item.name === name || item.typeName === name);
        return resource ? resource.offset : -1;
      },

      // --- version / manifest ---
      getFileVersion: () => (pe.versionInfo && pe.versionInfo.strings.FileVersion) || (pe.versionInfo && pe.versionInfo.fixed && pe.versionInfo.fixed.fileVersion) || "",
      getVersionStringInfo: key => (pe.versionInfo && pe.versionInfo.strings[key]) || "",
      getManifest: () => pe.manifest || "",

      // --- Rich header / debug / compiler ---
      isRichSignaturePresent: () => !!pe.rich,
      getNumberOfRichIDs: () => (pe.rich ? pe.rich.entries.length : 0),
      getRichID: index => (pe.rich && pe.rich.entries[index] ? pe.rich.entries[index].productId : 0),
      getRichVersion: index => (pe.rich && pe.rich.entries[index] ? pe.rich.entries[index].build : 0),
      getNumberOfDebugDataRecords: () => pe.debugRecords.length,
      getDebugDataType: index => {
        const type = pe.debugRecords[index] ? pe.debugRecords[index].type : 0;
        return ({
          1: "COFF", 2: "CODEVIEW", 3: "FPO", 4: "MISC", 5: "EXCEPTION", 6: "FIXUP",
          7: "OMAP_TO_SRC", 8: "OMAP_FROM_SRC", 9: "BORLAND", 10: "RESERVED10", 11: "CLSID",
          12: "VC_FEATURE", 13: "POGO", 14: "ILTCG", 15: "MPX", 16: "REPRO",
          17: "EX_DLLCHARACTERISTICS", 20: "PDB_CHECKSUM"
        })[type] || "UNKNOWN";
      },
      getDebugDataOffset: index => (pe.debugRecords[index] ? pe.debugRecords[index].offset : -1),
      getDebugDataSize: index => (pe.debugRecords[index] ? pe.debugRecords[index].size : 0),
      getCompilerVersion: () => "",
      getSectionNameCollision: () => "",

      // --- .NET ---
      isNet: () => pe.isNet,
      isNetObjectPresent: text => {
        if (!pe.isNet || !pe.net || pe.net.stringsStart < 0) return false;
        const needle = new TextEncoder().encode(String(text));
        return indexOfBytes(bytes, needle, pe.net.stringsStart, pe.net.stringsEnd) >= 0;
      },
      isNetUStringPresent: text => {
        if (!pe.isNet || !pe.net || pe.net.usStart < 0) return false;
        const encoded = new Uint8Array(String(text).length * 2);
        for (let i = 0; i < String(text).length; i++) {
          encoded[i * 2] = String(text).charCodeAt(i) & 0xff;
          encoded[i * 2 + 1] = String(text).charCodeAt(i) >>> 8;
        }
        return indexOfBytes(bytes, encoded, pe.net.usStart, pe.net.usEnd) >= 0;
      },
      getNetVersion: () => (pe.net ? pe.net.version : ""),
      getNETVersion: () => (pe.net ? pe.net.version : ""),
      getNetModuleName: () => (pe.net ? pe.net.moduleName || "" : ""),
      getNetAssemblyName: () => (pe.net ? pe.net.assemblyName || "" : ""),
      getNumberOfNetMethods: () => (pe.net ? pe.net.methodCount || 0 : 0),
      isNetTypePresent: (namespace, name) => !!(pe.net && pe.net.types && pe.net.types.some(type => type.namespace === (namespace || "") && type.name === name)),
      isNetGlobalCctorPresent: () => false,
      getNetUserString: () => "",
      isSignatureInBlobPresent_NET: signature => {
        if (!pe.net || pe.net.blobStart < 0) return false;
        const compiled = getCompiled(signature);
        return !!compiled && findInRange(api, compiled, pe.net.blobStart, pe.net.blobEnd - pe.net.blobStart, api.__budget) >= 0;
      },
      findSignatureInBlob_NET: signature => {
        if (!pe.net || pe.net.blobStart < 0) return -1;
        const compiled = getCompiled(signature);
        return compiled ? findInRange(api, compiled, pe.net.blobStart, pe.net.blobEnd - pe.net.blobStart, api.__budget) : -1;
      },

      // --- context used by the signature matcher ---
      bytes,
      size: bytes.length,
      offsetToAddress: offset => pe.offsetToAddress(offset),
      addressToOffset: address => pe.addressToOffset(address),
      nEP: pe.entryOffset,

      // --- misc that some signatures probe with typeof ---
      __budget: null
    };

    // Methods that must see the PE object as `this` if a signature rebinds them.
    api.File = api;
    api.Binary = api;
    return api;
  }

  function sectionOfDirectory(pe, index) {
    const directory = (pe.directories || [])[index];
    if (!directory || !directory.rva) return -1;
    for (const section of pe.sections) {
      const size = Math.max(section.virtualSize, section.rawSize);
      if (directory.rva >= section.virtualAddress && directory.rva < section.virtualAddress + size) return section.index;
    }
    return -1;
  }

  /* ------------------------------------------------------------------ *
   *  DiE-JS runtime
   * ------------------------------------------------------------------ */

  const DUPLICATE_THRESHOLDS = {
    tool: 2, sfx: 1, installer: 1, format: 2, archive: 2, "game engine": 1,
    "self-displayer": 1, linker: 1, compiler: 2, joiner: 2, packer: 2,
    cryptor: 2, protector: 3, protection: 3, library: 32
  };

  let helpersLoaded = false;
  function loadHelpers(bundle) {
    if (helpersLoaded || !bundle.helpers) return;
    // The official helpers only extend String/Number/Array prototypes.
    (0, eval)(bundle.helpers);
    helpersLoaded = true;
  }

  const initCache = new WeakMap();
  function initPE(pe, bundle) {
    if (!pe.valid || pe.__initDone) return pe;
    const run = new Function("PE", "PE_Cached", "DOTNET", "NET", "File", "Binary", "X",
      bundle.peInit + "\n;return PE;");
    const api = pe.api;
    run(api, api, api, api, api, api, api);
    pe.__initDone = true;
    api.File = api;
    api.Binary = api;
    return pe;
  }

  function inlineIncludes(source, includes, seen) {
    seen = seen || new Set();
    return String(source).replace(/includeScript\s*\(\s*["']([^"']+)["']\s*\)\s*;?/g, (match, name) => {
      if (seen.has(name) || !includes[name]) return "";
      seen.add(name);
      return "\n/* include: " + name + " */\n" + inlineIncludes(includes[name], includes, seen);
    });
  }

  function createSignatureFunction(signature, bundle) {
    if (signature.__fn) return signature.__fn;
    if (signature.__error) throw signature.__error;
    // meta()/result() must operate on the signature's own variables: DiE scripts
    // assign bDetected/sName/sVersion directly, then call result().
    const body = "var bDetected=false,sType='',sName='',sVersion='',sOptions='',sLang='',sLangVersion='';\n" +
      "function meta(t,n,v,o,l,lv){sType=t||'other';sName=n||'';sVersion=v||'';sOptions=o||'';sLang=l||'';sLangVersion=lv||'';bDetected=false;}\n" +
      "function result(){var d=bDetected;if(d){__collect(sType||'other',sName,sVersion||'',sOptions||'',sLang,sLangVersion);}sName=sVersion=sOptions=sLang=sLangVersion='';bDetected=false;return d;}\n" +
      inlineIncludes(signature.source, bundle.includes || {}) +
      "\n;if(typeof detect==='function'){detect();}";
    try {
      signature.__fn = new Function(
        "PE", "PE_Cached", "File", "Binary", "X", "DOTNET", "NET", "Tools", "Global",
        "__collect", "_setResult", "_setLang", "_isResultPresent", "_getNumberOfResults",
        "_removeResult", "_isLangPresent", "_isLangDetected", "_error", "_log", "_debug", "_isStop",
        body
      );
    } catch (error) {
      signature.__error = error;
      throw error;
    }
    return signature.__fn;
  }

  function runSignatures(pe, bundle, options) {
    options = options || {};
    const maxMs = options.maxMs || 25000;
    const startTime = Date.now();
    const budget = {
      expired: () => Date.now() - startTime > maxMs
    };
    const stats = {
      total: bundle.signatures.length,
      executed: 0,
      withResults: 0,
      errors: 0,
      skippedNoDetect: 0,
      aborted: false,
      elapsedMs: 0,
      missing: {},
      errorSamples: []
    };
    const results = [];
    const languages = [];

    if (!pe.valid) {
      stats.elapsedMs = 0;
      return { results, languages, stats, aborted: false };
    }

    // DiE's _FixDetects.rs post-processes earlier findings; keep it last so the
    // false-positive rules can see the results they are meant to remove.
    const ordered = bundle.signatures.filter(item => !item.fix).concat(bundle.signatures.filter(item => item.fix));
    stats.total = ordered.length;

    loadHelpers(bundle);
    initPE(pe, bundle);
    const api = pe.api;
    api.__budget = budget;

    const countByType = type => results.filter(item => item.type === type).length;
    const pushResult = record => {
      if (!record.name) return;
      const duplicate = results.some(item => item.type === record.type && item.name === record.name && item.version === record.version && item.options === record.options);
      if (!duplicate) results.push(record);
    };

    for (let index = 0; index < ordered.length; index++) {
      if (budget.expired()) { stats.aborted = true; break; }
      const signature = ordered[index];
      if (!signature.hasDetect) { stats.skippedNoDetect++; continue; }

      const localResults = [];
      const localLanguages = [];

      const collect = (type, name, version, opts, lang, langVersion) => {
        if (!name) return;
        const record = { type: type || "other", name, version: version || "", options: opts || "", source: signature.file };
        const threshold = DUPLICATE_THRESHOLDS[record.type];
        if (threshold === undefined || countByType(record.type) + localResults.filter(item => item.type === record.type).length <= threshold) {
          localResults.push(record);
        }
        if (lang) localLanguages.push({ name: lang, version: langVersion || "", source: signature.file });
      };
      const setResult = (type, name, version, opts) => {
        if (name) localResults.push({ type: type || "other", name, version: version || "", options: opts || "", source: signature.file });
      };
      const setLang = (name, version) => {
        if (name) localLanguages.push({ name, version: version || "", source: signature.file });
      };
      const isResultPresent = (type, name) => results.some(item => item.type === type && item.name === name) || localResults.some(item => item.type === type && item.name === name);
      const isLangPresent = name => languages.some(item => item.name === name) || localLanguages.some(item => item.name === name);
      const isLangDetected = () => languages.length + localLanguages.length > 0;
      const numberOfResults = type => results.filter(item => item.type === type).length + localResults.filter(item => item.type === type).length;
      const removeResult = (type, name) => {
        for (let i = localResults.length - 1; i >= 0; i--) if (localResults[i].type === type && localResults[i].name === name) localResults.splice(i, 1);
        for (let i = results.length - 1; i >= 0; i--) if (results[i].type === type && results[i].name === name) results.splice(i, 1);
      };
      const error = message => { throw new Error(String(message)); };
      const noop = () => {};
      const isStop = () => budget.expired();

      try {
        const fn = createSignatureFunction(signature, bundle);
        stats.executed++;
        fn(api, api, api, api, api, api, api, {}, {},
          collect, setResult, setLang, isResultPresent, numberOfResults, removeResult,
          isLangPresent, isLangDetected, error, noop, noop, isStop);
        for (const item of localResults) pushResult(item);
        for (const item of localLanguages) languages.push(item);
        if (localResults.length) stats.withResults++;
      } catch (thrown) {
        if (thrown === ABORT) { stats.aborted = true; break; }
        stats.errors++;
        const message = thrown && thrown.message ? thrown.message : String(thrown);
        const missing = /((?:PE|PE_Cached|DOTNET|File|Binary)\.\w+) is not a function/.exec(message);
        if (missing) stats.missing[missing[1]] = (stats.missing[missing[1]] || 0) + 1;
        if (stats.errorSamples.length < 12 && !missing) stats.errorSamples.push({ file: signature.file, message: message.slice(0, 180) });
      }
      if (options.onProgress && (index % 25 === 0 || index === ordered.length - 1)) {
        options.onProgress(index + 1, ordered.length);
      }
    }

    stats.elapsedMs = Date.now() - startTime;
    // Stable, type-oriented output for the UI.
    const order = ["protector", "packer", "cryptor", "protection", "compiler", "linker", "installer", "sfx", "joiner", "tool", "library", "game engine", "format", "archive", "other"];
    results.sort((a, b) => {
      const ai = order.indexOf(a.type); const bi = order.indexOf(b.type);
      return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi) || a.name.localeCompare(b.name);
    });
    const uniqueLanguages = [];
    const seen = new Set();
    for (const language of languages) {
      const key = language.name + "|" + language.version;
      if (seen.has(key)) continue;
      seen.add(key);
      uniqueLanguages.push(language);
    }
    return { results, languages: uniqueLanguages, stats, aborted: stats.aborted };
  }

  /* ------------------------------------------------------------------ *
   *  String extraction and clue classification
   * ------------------------------------------------------------------ */

  const STRING_PATTERNS = {
    flag: /(?:flag|ctf|key|pass(?:word)?|secret|token)\s*[=:]\s*[^\s"'<>]{3,120}/gi,
    flagBraces: /(?:flag|ctf|key|htb|picoctf|nssctf)\{[^}\r\n]{1,160}\}/gi,
    url: /\bhttps?:\/\/[^\s"'<>\\]{4,200}/gi,
    ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    registry: /\b(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"'<>]{3,200}/g,
    path: /\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]{1,80}\\){1,8}[^\\/:*?"<>|\r\n]{1,80}/g,
    email: /\b[\w.+-]{2,64}@[\w.-]{2,190}\.[A-Za-z]{2,12}\b/g,
    base64: /\b[A-Za-z0-9+/]{24,}={0,2}\b/g,
    upx: /\bUPX!?\b/g,
    pdb: /[A-Za-z]:\\[^\s"'<>]{3,200}\.pdb/gi
  };

  function extractStrings(bytes, limits) {
    limits = limits || {};
    const minAnsi = limits.minAnsi || 4;
    const minWide = limits.minWide || 4;
    const max = limits.max || 8000;
    const maxBytes = Math.min(bytes.length, limits.maxBytes || bytes.length);
    const ascii = [];
    const wide = [];
    const printable = value => value >= 0x20 && value < 0x7f;

    // ASCII runs.
    let start = -1;
    for (let i = 0; i < maxBytes && ascii.length < max; i++) {
      if (printable(bytes[i])) {
        if (start < 0) start = i;
      } else if (start >= 0) {
        if (i - start >= minAnsi) ascii.push({ offset: start, encoding: "ASCII", value: TEXT.decode(bytes.subarray(start, i)) });
        start = -1;
      }
    }
    if (start >= 0 && maxBytes - start >= minAnsi && ascii.length < max) {
      ascii.push({ offset: start, encoding: "ASCII", value: TEXT.decode(bytes.subarray(start, maxBytes)) });
    }

    // UTF-16LE runs: printable byte followed by a NUL, repeated.
    for (let i = 0; i + 1 < maxBytes && wide.length < max; i++) {
      if (!printable(bytes[i]) || bytes[i + 1] !== 0) continue;
      const begin = i;
      let end = i;
      while (end + 1 < maxBytes && printable(bytes[end]) && bytes[end + 1] === 0) end += 2;
      if ((end - begin) / 2 >= minWide && wide.length < max) {
        wide.push({ offset: begin, encoding: "UTF-16LE", value: utf16.decode(bytes.subarray(begin, end)) });
      }
      i = end - 1;
    }

    // Reserve a quarter of the budget for UTF-16 strings: .NET metadata and
    // Windows APIs often hide useful text there even when ASCII fills the cap.
    const wideReserve = Math.min(wide.length, Math.floor(max / 4));
    const asciiCap = max - wideReserve;
    let chosenAscii = ascii.slice(0, asciiCap);
    let chosenWide = wide.slice(0, wideReserve);
    if (chosenAscii.length < asciiCap) chosenWide = wide.slice(0, max - chosenAscii.length);
    const merged = chosenAscii.concat(chosenWide).sort((a, b) => a.offset - b.offset);
    return merged.slice(0, max);
  }

  function classifyStrings(strings) {
    const findings = {};
    const push = (key, value, offset, encoding) => {
      if (!findings[key]) findings[key] = [];
      if (findings[key].length >= 60) return;
      if (findings[key].some(item => item.value === value)) return;
      findings[key].push({ value, offset, encoding });
    };
    const limits = { flagBraces: 40, flag: 40, url: 60, ip: 60, registry: 40, path: 40, email: 40, base64: 20, upx: 10, pdb: 5 };
    for (const item of strings) {
      for (const [key, pattern] of Object.entries(STRING_PATTERNS)) {
        const bucket = findings[key] || (findings[key] = []);
        const limit = limits[key] || 40;
        if (bucket.length >= limit) continue;
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(item.value)) && bucket.length < limit) {
          push(key, match[0], item.offset, item.encoding);
        }
      }
    }
    return findings;
  }

  function packingHeuristics(pe) {
    const clues = [];
    const add = (severity, text) => clues.push({ severity, text });
    if (!pe.valid) return clues;

    const knownSections = [
      ["UPX0", "UPX"], ["UPX1", "UPX"], [".aspack", "ASPack"], [".adata", "ASPack"],
      [".vmp0", "VMProtect"], [".vmp1", "VMProtect"], [".themida", "Themida"], [".winlice", "WinLicense"],
      [".enigma1", "Enigma Protector"], [".enigma2", "Enigma Protector"], [".petite", "Petite"],
      [".nsp0", "NsPack"], [".nsp1", "NsPack"], [".MPRESS1", "MPRESS"], [".MPRESS2", "MPRESS"],
      [".packed", "通用加壳节名"], [".RLPack", "RLPack"], [".perplex", "Perplex"], [".pklstb", "PKLSTB"],
      [".yP", "Y0da Protector"], [".y0da", "Y0da Protector"], [".pec", "PECompact"], [".pec1", "PECompact"],
      [".ccg", "CCG"], [".charmve", "Charmve"], [".boom", "The Boomerang"]
    ];
    for (const section of pe.sections) {
      const hit = knownSections.find(([name]) => section.name.toLowerCase() === name.toLowerCase());
      const displayName = section.name || "(无名)";
      if (hit) add("warning", `节区 ${displayName} 与 ${hit[1]} 的常见节名一致。`);
      if (section.writable && section.executable) add("warning", `节区 ${displayName} 同时具备可写和可执行权限（W+X）。`);
      if (section.executable && section.entropy >= 7.2 && section.rawSize > 4096) {
        add("info", `可执行节区 ${displayName} 的熵为 ${section.entropy} bits/byte，接近加密/压缩数据。`);
      }
      if (!section.rangeValid) add("warning", `节区 ${displayName} 的原始数据超出文件末尾。`);
    }
    if (pe.entryOffset >= 0) {
      const entrySection = pe.sections[pe.entrySection];
      if (entrySection && entrySection.name !== ".text" && entrySection.executable) {
        add("info", `入口点位于 ${entrySection.name || "(无名)"}，而不是常见的 .text 节。`);
      }
      if (!entrySection) add("warning", "入口点不落在任何节区中。");
      if (pe.entryOffset < pe.sizeOfHeaders && pe.entryRva !== 0) add("warning", "入口点位于 PE 头部区域。");
    }
    if (pe.imports.length === 0) add("warning", "文件没有常规导入表；可能被加壳、修复过，或为特殊构造样本。");
    else if (pe.imports.reduce((sum, lib) => sum + lib.functions.length, 0) < 8) {
      add("info", "导入函数数量少于 8 个，常见于加壳或手工构造的小样本。");
    }
    if (pe.overlaySize > 0) {
      const ratio = pe.overlaySize / Math.max(1, bytesLength(pe));
      add(ratio > 0.2 ? "warning" : "info", `文件尾部附加数据 ${pe.overlaySize.toLocaleString("en-US")} 字节（约占 ${(ratio * 100).toFixed(1)}%）。`);
    }
    if (pe.entryBytes && /^(60|9C|E8|EB)/.test(pe.entryBytes)) {
      add("info", `入口点起始字节为 ${pe.entryBytes.slice(0, 12)}，常见于壳/自解压的引导代码。`);
    }
    return clues;
  }

  function bytesLength(pe) { return pe.size; }

  return {
    parsePE,
    createAPI,
    compileSignature,
    matchesAt,
    findInRange,
    runSignatures,
    extractStrings,
    classifyStrings,
    packingHeuristics,
    customCRC32,
    entropyOf,
    STRING_PATTERNS
  };
});
