/*
 * APK 静态检查：Android 二进制 XML（AXML）与 resources.arsc 读取。
 * 只做只读解析，不执行、不重建 APK。
 */
(() => {
  'use strict';

  const root = typeof globalThis !== 'undefined' ? globalThis : window;
  const Api = root.ApkInspect = root.ApkInspect || {};
  const U = Api.util;

  const ANDROID_NS = 'http://schemas.android.com/apk/res/android';
  const NO_ENTRY = 0xffffffff;

  /* ------------------------------------------------------------------ */
  /* 字符串池（AXML 与 ARSC 共用）                                        */
  /* ------------------------------------------------------------------ */

  const UTF8_FLAG = 0x100;

  function readLength8(bytes, offset) {
    let value = bytes[offset];
    if (value & 0x80) return { length: ((value & 0x7f) << 8) | bytes[offset + 1], next: offset + 2 };
    return { length: value, next: offset + 1 };
  }
  function readLength16(bytes, offset) {
    let value = U.readU16(bytes, offset);
    if (value & 0x8000) return { length: ((value & 0x7fff) << 16) | U.readU16(bytes, offset + 2), next: offset + 4 };
    return { length: value, next: offset + 2 };
  }
  function decodeUtf8String(bytes, offset) {
    const first = readLength8(bytes, offset);
    const second = readLength8(bytes, first.next);
    const start = second.next;
    return U.utf8(bytes.subarray(start, start + second.length));
  }
  function decodeUtf16String(bytes, offset) {
    const length = readLength16(bytes, offset);
    const start = length.next;
    let text = '';
    for (let i = 0; i < length.length; i++) text += String.fromCharCode(U.readU16(bytes, start + i * 2));
    return text;
  }

  function parseStringPool(bytes, start) {
    const type = U.readU16(bytes, start);
    const headerSize = U.readU16(bytes, start + 2);
    const size = U.readU32(bytes, start + 4);
    if (type !== 0x0001) throw new Error('字符串池块类型无效：0x' + type.toString(16));
    if (start + size > bytes.length) throw new Error('字符串池超出数据范围。');
    const stringCount = U.readU32(bytes, start + 8);
    const styleCount = U.readU32(bytes, start + 12);
    const flags = U.readU32(bytes, start + 16);
    const stringsStart = U.readU32(bytes, start + 20);
    const stylesStart = U.readU32(bytes, start + 24);
    if (stringCount > 500000) throw new Error('字符串池条目数量异常：' + stringCount);
    const offsets = [];
    for (let i = 0; i < stringCount; i++) {
      const offset = U.readU32(bytes, start + headerSize + i * 4);
      if (offset >= size) { offsets.push(-1); continue; }
      offsets.push(offset);
    }
    const strings = new Array(stringCount);
    const base = start + stringsStart;
    const utf8 = Boolean(flags & UTF8_FLAG);
    for (let i = 0; i < stringCount; i++) {
      if (offsets[i] < 0) { strings[i] = ''; continue; }
      try {
        strings[i] = utf8 ? decodeUtf8String(bytes, base + offsets[i]) : decodeUtf16String(bytes, base + offsets[i]);
      } catch {
        strings[i] = '';
      }
    }
    return { strings, stringCount, styleCount, flags, utf8, stylesStart, size };
  }

  /* ------------------------------------------------------------------ */
  /* AXML                                                                 */
  /* ------------------------------------------------------------------ */

  const TYPE = {
    NULL: 0x00, REFERENCE: 0x01, ATTRIBUTE: 0x02, STRING: 0x03, FLOAT: 0x04,
    DIMENSION: 0x05, FRACTION: 0x06, INT_DEC: 0x10, INT_HEX: 0x11, INT_BOOLEAN: 0x12,
    INT_COLOR_ARGB8: 0x1c, INT_COLOR_RGB8: 0x1d, INT_COLOR_ARGB4: 0x1e, INT_COLOR_RGB4: 0x1f
  };
  const DIMENSION_UNITS = ['px', 'dp', 'sp', 'pt', 'in', 'mm'];
  const FRACTION_UNITS = ['%', '%p'];

  function complexToFloat(data) {
    const radix = (data >> 4) & 0x03;
    const divisor = radix === 0 ? 1 << 8 : radix === 1 ? 1 << 7 : radix === 2 ? 1 << 15 : 1 << 23;
    return ((data | 0) >> 8) / divisor;
  }
  function typedValueText(type, data, strings) {
    switch (type) {
      case TYPE.NULL: return '';
      case TYPE.REFERENCE: return '@0x' + (data >>> 0).toString(16);
      case TYPE.ATTRIBUTE: return '?0x' + (data >>> 0).toString(16);
      case TYPE.STRING: return strings[data] ?? '@string#' + data;
      case TYPE.FLOAT: {
        const view = new DataView(new ArrayBuffer(4));
        view.setUint32(0, data >>> 0, true);
        return String(view.getFloat32(0, true));
      }
      case TYPE.DIMENSION: {
        const unit = DIMENSION_UNITS[data & 0xf] || '';
        return complexToFloat(data).toFixed(2) + unit;
      }
      case TYPE.FRACTION: {
        const unit = FRACTION_UNITS[(data >> 4) & 0x1] || '';
        return (complexToFloat(data) * 100).toFixed(2) + unit;
      }
      case TYPE.INT_DEC: return String(data | 0);
      case TYPE.INT_HEX: return '0x' + (data >>> 0).toString(16);
      case TYPE.INT_BOOLEAN: return data !== 0 ? 'true' : 'false';
      default:
        if (type >= TYPE.INT_COLOR_ARGB8 && type <= TYPE.INT_COLOR_RGB4) return '#0x' + (data >>> 0).toString(16).padStart(8, '0');
        return '0x' + (data >>> 0).toString(16) + '（类型 0x' + type.toString(16) + '）';
    }
  }

  function parseAxml(bytes) {
    if (bytes.length < 8) throw new Error('AndroidManifest.xml 数据过短。');
    const magic = U.readU16(bytes, 0);
    if (magic !== 0x0003) throw new Error('不是 Android 二进制 XML（文件头 0x' + magic.toString(16) + '）。');
    const fileSize = U.readU32(bytes, 4);
    if (fileSize > bytes.length) throw new Error('二进制 XML 声明的长度超出数据范围，可能已截断。');
    let offset = U.readU16(bytes, 2);
    let strings = [];
    let resourceMap = [];
    const namespaces = [];
    const uriToPrefix = new Map();
    const roots = [];
    const stack = [];
    let document = null;
    while (offset + 8 <= bytes.length) {
      const type = U.readU16(bytes, offset);
      const headerSize = U.readU16(bytes, offset + 2);
      const chunkSize = U.readU32(bytes, offset + 4);
      if (!chunkSize || offset + chunkSize > bytes.length) break;
      if (type === 0x0001) {
        strings = parseStringPool(bytes, offset).strings;
      } else if (type === 0x0180) {
        const count = (chunkSize - headerSize) / 4;
        for (let i = 0; i < count; i++) resourceMap.push(U.readU32(bytes, offset + headerSize + i * 4));
      } else if (type === 0x0100) {
        const prefix = strings[U.readU32(bytes, offset + 16)] || '';
        const uri = strings[U.readU32(bytes, offset + 20)] || '';
        namespaces.push({ prefix, uri });
        uriToPrefix.set(uri, prefix);
      } else if (type === 0x0101) {
        // 结束命名空间无需处理；保留全部声明供序列化使用。
      } else if (type === 0x0102) {
        const name = strings[U.readU32(bytes, offset + 20)] || '';
        const namespaceIndex = U.readU32(bytes, offset + 16);
        const attributeStart = U.readU16(bytes, offset + 24);
        const attributeSize = U.readU16(bytes, offset + 26) || 20;
        const attributeCount = U.readU16(bytes, offset + 28);
        const attrs = [];
        for (let i = 0; i < attributeCount; i++) {
          // attributeStart 相对于 ResXMLTree_attrExt（节点头 16 字节之后）计算。
          const attrOffset = offset + 16 + attributeStart + i * attributeSize;
          if (attrOffset + 20 > offset + chunkSize) break;
          const nsIndex = U.readU32(bytes, attrOffset);
          const nameIndex = U.readU32(bytes, attrOffset + 4);
          const rawIndex = U.readU32(bytes, attrOffset + 8);
          const valueType = bytes[attrOffset + 15];
          const valueData = U.readU32(bytes, attrOffset + 16);
          const attrName = strings[nameIndex] ?? '';
          const nsUri = nsIndex === NO_ENTRY ? '' : (strings[nsIndex] ?? '');
          const raw = rawIndex === NO_ENTRY ? null : (strings[rawIndex] ?? null);
          const display = raw !== null ? raw : typedValueText(valueType, valueData, strings);
          attrs.push({
            ns: nsUri,
            prefix: nsUri ? (uriToPrefix.get(nsUri) || '') : '',
            name: attrName,
            qname: nsUri ? (uriToPrefix.get(nsUri) || '') + ':' + attrName : attrName,
            value: display,
            raw,
            type: valueType,
            data: valueData,
            reference: valueType === TYPE.REFERENCE ? valueData >>> 0 : null
          });
        }
        const element = { name, namespace: namespaceIndex === NO_ENTRY ? '' : (strings[namespaceIndex] || ''), attrs, children: [] };
        if (stack.length) stack[stack.length - 1].children.push(element);
        else roots.push(element);
        stack.push(element);
      } else if (type === 0x0103) {
        stack.pop();
      }
      offset += chunkSize;
    }
    if (!roots.length) throw new Error('二进制 XML 中没有找到根元素。');
    document = { roots, root: roots[0], strings, resourceMap, namespaces };
    return document;
  }

  function escapeXml(value) {
    return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  }
  function serializeAxml(document) {
    const prefixes = new Map();
    const namespaces = document.namespaces || [];
    for (const item of namespaces) prefixes.set(item.uri, item.prefix || '');
    const lines = ['<?xml version="1.0" encoding="utf-8"?>'];
    let generated = 0;
    function attrsText(element, isRoot) {
      const list = [];
      if (isRoot) {
        for (const item of namespaces) {
          if (!item.prefix) continue;
          list.push('xmlns:' + item.prefix + '="' + escapeXml(item.uri) + '"');
        }
      }
      for (const attr of element.attrs) {
        let name = attr.name;
        if (attr.ns) {
          let prefix = prefixes.get(attr.ns);
          if (prefix === undefined) { prefix = 'ns' + (++generated); prefixes.set(attr.ns, prefix); }
          name = (prefix ? prefix + ':' : '') + attr.name;
        }
        list.push(name + '="' + escapeXml(attr.value) + '"');
      }
      return list.length ? ' ' + list.join(' ') : '';
    }
    function visit(element, depth, isRoot) {
      const indent = '  '.repeat(depth);
      const attrs = attrsText(element, isRoot);
      if (!element.children.length) {
        lines.push(indent + '<' + element.name + attrs + '/>');
        return;
      }
      lines.push(indent + '<' + element.name + attrs + '>');
      for (const child of element.children) visit(child, depth + 1, false);
      lines.push(indent + '</' + element.name + '>');
    }
    const roots = document.roots || (document.root ? [document.root] : []);
    roots.forEach((element, index) => visit(element, 0, index === 0));
    return lines.join('\n');
  }
  /* ------------------------------------------------------------------ */
  /* resources.arsc                                                       */
  /* ------------------------------------------------------------------ */

  function decodeConfig(bytes, start, size) {
    const config = { size, language: '', country: '', density: 0, sdkVersion: 0, label: '默认' };
    if (size >= 12) {
      const language = bytes.subarray(start + 8, start + 10);
      const country = bytes.subarray(start + 10, start + 12);
      config.language = language[0] ? String.fromCharCode(language[0]) + (language[1] ? String.fromCharCode(language[1]) : '') : '';
      config.country = country[0] ? String.fromCharCode(country[0]) + (country[1] ? String.fromCharCode(country[1]) : '') : '';
    }
    if (size >= 16) config.density = U.readU16(bytes, start + 14);
    if (size >= 26) config.sdkVersion = U.readU16(bytes, start + 24);
    let label = config.language ? config.language + (config.country ? '-' + config.country : '') : '默认';
    if (config.density) label += ' · ' + config.density + 'dpi';
    if (config.sdkVersion) label += ' · SDK ' + config.sdkVersion;
    config.label = label;
    return config;
  }

  function formatValue(dataType, data, stringPool, depth) {
    if (dataType === TYPE.STRING) return stringPool[data] ?? '';
    if (dataType === TYPE.REFERENCE) return { reference: data >>> 0, text: '@0x' + (data >>> 0).toString(16) };
    return typedValueText(dataType, data, stringPool);
  }

  function parseArsc(bytes) {
    if (bytes.length < 12 || U.readU16(bytes, 0) !== 0x0002) throw new Error('不是 resources.arsc 资源表。');
    const headerSize = U.readU16(bytes, 2);
    const packageCount = U.readU32(bytes, 8);
    let offset = headerSize;
    let stringPool = [];
    const packages = [];
    while (offset + 8 <= bytes.length) {
      const type = U.readU16(bytes, offset);
      const chunkHeaderSize = U.readU16(bytes, offset + 2);
      const chunkSize = U.readU32(bytes, offset + 4);
      if (!chunkSize || offset + chunkSize > bytes.length) break;
      if (type === 0x0001) {
        stringPool = parseStringPool(bytes, offset).strings;
      } else if (type === 0x0200) {
        packages.push(parsePackage(bytes, offset, chunkHeaderSize, chunkSize, stringPool));
      }
      offset += chunkSize;
    }
    const entries = new Map();
    let stringCount = 0;
    let resourceCount = 0;
    for (const pkg of packages) {
      for (const typeInfo of pkg.types) {
        for (const entry of typeInfo.entries) {
          const id = ((pkg.id << 24) | (typeInfo.id << 16) | entry.index) >>> 0;
          if (!entries.has(id)) entries.set(id, []);
          entries.get(id).push({
            id,
            package: pkg.name,
            type: typeInfo.name,
            key: entry.key,
            config: entry.config,
            dataType: entry.dataType,
            data: entry.data,
            value: entry.value,
            isComplex: entry.isComplex
          });
          resourceCount++;
          if (typeInfo.name === 'string' && typeof entry.value === 'string') stringCount++;
        }
      }
    }
    return { packages, stringPool, entries, stringCount, resourceCount, packageCount };
  }

  function parsePackage(bytes, start, headerSize, size, stringPool) {
    const id = U.readU32(bytes, start + 8);
    let name = '';
    for (let i = 0; i < 128; i++) {
      const code = U.readU16(bytes, start + 12 + i * 2);
      if (!code) break;
      name += String.fromCharCode(code);
    }
    const typeStringsOffset = U.readU32(bytes, start + 268);
    const keyStringsOffset = U.readU32(bytes, start + 276);
    const typePool = typeStringsOffset && typeStringsOffset < size ? parseStringPool(bytes, start + typeStringsOffset) : { strings: [] };
    const keyPool = keyStringsOffset && keyStringsOffset < size ? parseStringPool(bytes, start + keyStringsOffset) : { strings: [] };
    const types = [];
    let offset = start + headerSize;
    while (offset + 8 <= start + size) {
      const type = U.readU16(bytes, offset);
      const chunkHeaderSize = U.readU16(bytes, offset + 2);
      const chunkSize = U.readU32(bytes, offset + 4);
      if (!chunkSize || offset + chunkSize > start + size) break;
      if (type === 0x0201) {
        types.push(parseType(bytes, offset, chunkHeaderSize, chunkSize, typePool.strings, keyPool.strings, stringPool));
      }
      offset += chunkSize;
    }
    return { id, name, typePool: typePool.strings, keyPool: keyPool.strings, types };
  }

  function parseType(bytes, start, headerSize, size, typeNames, keyNames, stringPool) {
    const id = bytes[start + 8];
    const flags = bytes[start + 9];
    const entryCount = U.readU32(bytes, start + 12);
    const entriesStart = U.readU32(bytes, start + 16);
    const configSize = U.readU32(bytes, start + 20);
    const config = decodeConfig(bytes, start + 20, configSize);
    const name = typeNames[id - 1] || ('type' + id);
    const entries = [];
    const limit = Math.min(entryCount, 200000);
    const offsetsStart = start + headerSize;
    const sparse = Boolean(flags & 0x01);
    const offset16 = Boolean(flags & 0x02);
    const readEntryAt = (index, entryOffset) => {
      const entryStart = start + entriesStart + entryOffset;
      if (entryStart + 8 > start + size) return;
      const entrySize = U.readU16(bytes, entryStart);
      const entryFlags = U.readU16(bytes, entryStart + 2);
      const keyIndex = U.readU32(bytes, entryStart + 4);
      const key = keyNames[keyIndex] || ('0x' + index.toString(16));
      if (entryFlags & 0x0001) {
        entries.push({ index, key, config, isComplex: true, dataType: TYPE.NULL, data: 0, value: '（复杂资源/样式）' });
        return;
      }
      if (entrySize < 8 || entryStart + entrySize + 8 > start + size) return;
      const valueOffset = entryStart + entrySize;
      const dataType = bytes[valueOffset + 3];
      const data = U.readU32(bytes, valueOffset + 4);
      let value = formatValue(dataType, data, stringPool);
      if (value && typeof value === 'object') value = value.text;
      entries.push({ index, key, config, isComplex: false, dataType, data, value });
    };
    for (let i = 0; i < limit; i++) {
      if (sparse) {
        const pairOffset = offsetsStart + i * 4;
        if (pairOffset + 4 > start + size) break;
        const index = U.readU16(bytes, pairOffset);
        const entryOffset = U.readU16(bytes, pairOffset + 2) * 4;
        readEntryAt(index, entryOffset);
      } else if (offset16) {
        const offsetLocation = offsetsStart + i * 2;
        if (offsetLocation + 2 > start + size) break;
        const raw = U.readU16(bytes, offsetLocation);
        if (raw === 0xffff) continue;
        readEntryAt(i, raw * 4);
      } else {
        const offsetLocation = offsetsStart + i * 4;
        if (offsetLocation + 4 > start + size) break;
        const raw = U.readU32(bytes, offsetLocation);
        if (raw === NO_ENTRY) continue;
        readEntryAt(i, raw);
      }
    }
    return { id, name, flags, config, entries };
  }

  function configPriority(config) {
    let score = 0;
    if (config.language) score -= 100;
    if (config.density) score -= 10;
    if (config.sdkVersion) score -= 1;
    return score;
  }
  function pickDefault(list) {
    if (!list || !list.length) return null;
    return [...list].sort((a, b) => configPriority(b.config) - configPriority(a.config))[0];
  }
  function resolveResource(table, id, depth = 0) {
    if (!table || depth > 6) return null;
    const candidates = table.entries.get(id >>> 0);
    const picked = pickDefault(candidates);
    if (!picked) return null;
    if (picked.dataType === TYPE.REFERENCE && (picked.data >>> 0) !== (id >>> 0)) return resolveResource(table, picked.data >>> 0, depth + 1);
    return picked;
  }
  function collectStringResources(table, limit = 4000) {
    const items = [];
    const seen = new Set();
    let total = 0;
    const locales = new Map();
    if (!table) return { items, total, locales: [] };
    for (const pkg of table.packages) {
      for (const typeInfo of pkg.types) {
        if (typeInfo.name !== 'string') continue;
        for (const entry of typeInfo.entries) {
          if (typeof entry.value !== 'string' || !entry.value) continue;
          total++;
          locales.set(entry.config.label, (locales.get(entry.config.label) || 0) + 1);
          if (items.length >= limit) continue;
          const signature = entry.key + '\u0000' + entry.config.label + '\u0000' + entry.value;
          if (seen.has(signature)) continue;
          seen.add(signature);
          items.push({ name: entry.key, value: entry.value, config: entry.config.label });
        }
      }
    }
    return {
      items,
      total,
      locales: [...locales.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count)
    };
  }

  Object.assign(Api, {
    ANDROID_NS,
    axml: { parse: parseAxml, serialize: serializeAxml },
    arsc: { parse: parseArsc, resolveResource, collectStringResources, pickDefault }
  });
  if (typeof module === 'object' && module.exports) module.exports = Api;
})();
