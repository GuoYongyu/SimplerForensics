(() => {
  const $ = selector => document.querySelector(selector);
  const input = $('#file');
  const resultPanel = $('#results');
  const rows = $('#metadata-rows');
  const status = $('#status');
  const MAX_FILE_SIZE = 128 * 1024 * 1024;
  const MAX_FIELDS = 300;
  const fields = [];
  const warnings = [];

  const addField = (category, name, value, offset, length) => {
    if (value === undefined || value === null || value === '') return;
    if (fields.length >= MAX_FIELDS) { warn(`结果达到 ${MAX_FIELDS} 个字段上限。`); return; }
    const text = String(value);
    fields.push({ category, name, value: text.length > 2048 ? `${text.slice(0, 2048)}…（内容已截断）` : text, offset, length });
  };
  const warn = message => { if (!warnings.includes(message)) warnings.push(message); };
  const u32le = (view, offset) => view.getUint32(offset, true);
  const hexOffset = offset => offset === null || offset === undefined ? '—' : `${offset.toLocaleString()} (0x${offset.toString(16).toUpperCase()})`;
  const decodeText = bytes => new TextDecoder('utf-8', { fatal: false }).decode(bytes).replace(/\0+$/g, '').trim();
  const latin1 = bytes => {
    const parts = [];
    for (let offset = 0; offset < bytes.length; offset += 8192) parts.push(String.fromCharCode(...bytes.subarray(offset, offset + 8192)));
    return parts.join('').replace(/\0+$/g, '').trim();
  };

  function parseTiff(bytes, baseOffset = 0, category = 'TIFF / EXIF') {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const localFields = [];
    const checked = (offset, length) => Number.isSafeInteger(offset) && offset >= 0 && length >= 0 && offset + length <= bytes.length;
    const fail = message => { warn(message); return localFields; };
    let start = 0;
    if (bytes.length >= 6 && latin1(bytes.subarray(0, 6)) === 'Exif') start = 6;
    if (!checked(start, 8)) return fail('TIFF/EXIF 头部不完整。');
    const order = latin1(bytes.subarray(start, start + 2));
    if (order !== 'II' && order !== 'MM') return fail('无法识别 TIFF 字节序标记。');
    const little = order === 'II';
    addField(category, '字节序', little ? '小端 (II)' : '大端 (MM)', baseOffset + start, 2);
    const read16 = offset => view.getUint16(offset, little);
    const read32 = offset => view.getUint32(offset, little);
    if (read16(start + 2) !== 42) return fail('TIFF 魔数不匹配，未解析 IFD。');
    const typeSize = { 1:1, 2:1, 3:2, 4:4, 5:8, 6:1, 7:1, 8:2, 9:4, 10:8 };
    const tagNames = {
      0x0100:'图像宽度',0x0101:'图像高度',0x010e:'图像描述',0x010f:'设备制造商',0x0110:'设备型号',
      0x0112:'方向',0x0131:'软件',0x0132:'修改时间',0x013b:'作者',0x8298:'版权',
      0x829a:'曝光时间',0x829d:'光圈值',0x8827:'ISO 感光度',0x9003:'原始拍摄时间',
      0x9004:'数字化时间',0x920a:'焦距',0xa434:'镜头型号',0x0001:'GPS 纬度参考',
      0x0002:'GPS 纬度',0x0003:'GPS 经度参考',0x0004:'GPS 经度',0x0005:'GPS 海拔参考',
      0x0006:'GPS 海拔',0x001d:'GPS 日期'
    };
    const rational = (at, signed = false) => {
      const numerator = signed ? view.getInt32(at, little) : read32(at);
      const denominator = signed ? view.getInt32(at + 4, little) : read32(at + 4);
      if (denominator === 0) return '分母为 0';
      const value = numerator / denominator;
      return `${Number.isFinite(value) ? Number(value.toPrecision(8)) : value} (${numerator}/${denominator})`;
    };
    const decode = (type, count, valueOffset, inlineOffset, itemOffset) => {
      const unit = typeSize[type];
      if (!unit || count > 100000) return null;
      const length = unit * count;
      const dataOffset = length <= 4 ? inlineOffset : valueOffset;
      if (!checked(dataOffset, length)) return null;
      if (type === 2 || type === 7) return type === 2 ? latin1(bytes.subarray(dataOffset, dataOffset + length)) : Array.from(bytes.subarray(dataOffset, dataOffset + Math.min(length, 64)), v => v.toString(16).padStart(2, '0').toUpperCase()).join(' ');
      if (type === 5 || type === 10) {
        const countToShow = Math.min(count, 10);
        return Array.from({ length: countToShow }, (_, index) => rational(dataOffset + index * 8, type === 10)).join(', ');
      }
      const values = [];
      const countToShow = Math.min(count, 16);
      for (let i = 0; i < countToShow; i++) {
        const at = dataOffset + i * unit;
        values.push(type === 3 ? read16(at) : type === 4 ? read32(at) : type === 8 ? view.getInt16(at, little) : type === 9 ? view.getInt32(at, little) : bytes[at]);
      }
      return `${values.join(', ')}${count > countToShow ? ', …' : ''}`;
    };
    const queue = [{ kind:'IFD0', offset:read32(start + 4) }];
    const visited = new Set();
    while (queue.length && localFields.length < MAX_FIELDS) {
      const current = queue.shift();
      if (!current.offset || visited.has(`${current.kind}:${current.offset}`)) continue;
      visited.add(`${current.kind}:${current.offset}`);
      const ifd = start + current.offset;
      if (!checked(ifd, 2)) { warn(`${current.kind} 偏移超出 TIFF/EXIF 数据范围。`); continue; }
      const count = read16(ifd);
      if (count > 4096 || !checked(ifd + 2, count * 12 + 4)) { warn(`${current.kind} 条目数或长度异常，停止读取该目录。`); continue; }
      for (let i = 0; i < count; i++) {
        const entry = ifd + 2 + i * 12;
        const tag = read16(entry), type = read16(entry + 2), itemCount = read32(entry + 4);
        const valueOffset = read32(entry + 8);
        const dataOffset = start + valueOffset;
        const name = tagNames[tag] || `${current.kind} 标签 0x${tag.toString(16).toUpperCase().padStart(4, '0')}`;
        const value = decode(type, itemCount, dataOffset, entry + 8, entry);
        if (value !== null) {
          const item = { category, name, value, offset:baseOffset + entry, length:12 };
          localFields.push(item);
          if (fields.length + localFields.length >= MAX_FIELDS) break;
        } else if (typeSize[type]) warn(`${name} 数据偏移或长度超出文件范围。`);
        if (current.kind === 'IFD0' && tag === 0x8769 && itemCount === 1) queue.push({ kind:'EXIF', offset:valueOffset });
        if (current.kind === 'IFD0' && tag === 0x8825 && itemCount === 1) queue.push({ kind:'GPS', offset:valueOffset });
      }
      const next = read32(ifd + 2 + count * 12);
      if (current.kind === 'IFD0' && next) queue.push({ kind:'IFD1', offset:next });
    }
    fields.push(...localFields);
    if (fields.length >= MAX_FIELDS) warn(`结果达到 ${MAX_FIELDS} 个字段上限。`);
    if (localFields.some(item => /GPS (?:纬度|经度|海拔)/.test(item.name))) warn('EXIF 中包含 GPS 字段；坐标当前按原始有理数呈现，请注意位置隐私。');
    if (localFields.some(item => /(?:拍摄|数字化|修改)时间/.test(item.name))) warn('EXIF 日期通常没有时区信息；本工具保留原始值，不进行时区推断。');
    return localFields;
  }

  function parseJpeg(bytes, fileOffset = 0) {
    addField('JPEG', '文件标记', 'SOI (FFD8)', fileOffset, 2);
    let position = 2, segments = 0;
    while (position + 4 <= bytes.length && segments++ < 20000) {
      if (bytes[position] !== 0xff) { warn(`JPEG 标记扫描在偏移 ${fileOffset + position} 处停止。`); break; }
      while (bytes[position] === 0xff) position++;
      if (position >= bytes.length) break;
      const marker = bytes[position++];
      if (marker === 0xd9) { addField('JPEG', '结束标记', 'EOI (FFD9)', fileOffset + position - 2, 2); break; }
      if (marker === 0xda) { addField('JPEG', '扫描数据', 'SOS 后为压缩图像数据；未解析熵编码区。', fileOffset + position - 2, 2); break; }
      if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
      if (position + 2 > bytes.length) { warn('JPEG 段长度字段不完整。'); break; }
      const length = bytes[position] * 256 + bytes[position + 1];
      if (length < 2 || position + length > bytes.length) { warn(`JPEG 段在偏移 ${fileOffset + position - 2} 处超出可读范围。`); break; }
      const dataOffset = position + 2, dataLength = length - 2;
      if (marker === 0xe1 && dataLength >= 6 && latin1(bytes.subarray(dataOffset, dataOffset + 6)) === 'Exif\0\0') {
        addField('JPEG', 'APP1 EXIF 段', `${dataLength.toLocaleString()} 字节`, fileOffset + position - 2, length + 2);
        parseTiff(bytes.subarray(dataOffset, dataOffset + dataLength), fileOffset + dataOffset, 'JPEG / EXIF');
      } else if (marker === 0xe0 && dataLength >= 5 && latin1(bytes.subarray(dataOffset, dataOffset + 5)) === 'JFIF\0') {
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        if (dataLength >= 12) {
          addField('JPEG / JFIF', '版本', `${bytes[dataOffset + 5]}.${bytes[dataOffset + 6]}`, fileOffset + dataOffset + 5, 2);
          addField('JPEG / JFIF', '像素密度单位', ({0:'无单位',1:'每英寸',2:'每厘米'})[bytes[dataOffset + 7]] || `未知 (${bytes[dataOffset + 7]})`, fileOffset + dataOffset + 7, 1);
          addField('JPEG / JFIF', '水平像素密度', view.getUint16(dataOffset + 8, false), fileOffset + dataOffset + 8, 2);
          addField('JPEG / JFIF', '垂直像素密度', view.getUint16(dataOffset + 10, false), fileOffset + dataOffset + 10, 2);
        }
      } else if (marker === 0xfe) {
        addField('JPEG', '注释', decodeText(bytes.subarray(dataOffset, dataOffset + dataLength)), fileOffset + dataOffset, dataLength);
      }
      position += length;
    }
    if (segments >= 20000) warn('JPEG 段数量超过扫描上限。');
  }

  function parsePng(bytes, fileOffset = 0) {
    addField('PNG', '文件标记', 'PNG signature', fileOffset, 8);
    let position = 8, chunks = 0;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const names = { IHDR:'图像头',tEXt:'文本',zTXt:'压缩文本',iTXt:'国际文本',tIME:'修改时间',eXIf:'EXIF',pHYs:'像素密度',sRGB:'色彩空间',gAMA:'伽马值' };
    while (position + 12 <= bytes.length && chunks++ < 100000) {
      const length = view.getUint32(position, false);
      const type = latin1(bytes.subarray(position + 4, position + 8));
      if (length > bytes.length - position - 12) { warn(`PNG ${type} 块长度超出可读范围。`); break; }
      const start = position + 8, end = start + length;
      if (type === 'IHDR' && length >= 13) {
        addField('PNG', '像素宽度', view.getUint32(start, false), fileOffset + start, 4);
        addField('PNG', '像素高度', view.getUint32(start + 4, false), fileOffset + start + 4, 4);
        addField('PNG', '位深 / 颜色类型', `${bytes[start + 8]} / ${bytes[start + 9]}`, fileOffset + start + 8, 2);
      } else if (type === 'tEXt') {
        const zero = bytes.indexOf(0, start);
        if (zero > start && zero < end) addField('PNG / tEXt', latin1(bytes.subarray(start, zero)), latin1(bytes.subarray(zero + 1, end)), fileOffset + start, length);
        else warn('PNG tEXt 关键词分隔符无效。');
      } else if (type === 'iTXt') {
        const zero = bytes.indexOf(0, start);
        if (zero > start && zero < end && zero + 3 < end) {
          const keyword = latin1(bytes.subarray(start, zero));
          const compressed = bytes[zero + 1] !== 0;
          let cursor = zero + 3;
          for (let n = 0; n < 2; n++) { const next = bytes.indexOf(0, cursor); if (next < 0 || next >= end) { cursor = end; break; } cursor = next + 1; }
          if (compressed) warn(`PNG iTXt 字段“${keyword}”使用压缩文本，当前未解压。`);
          else addField('PNG / iTXt', keyword, decodeText(bytes.subarray(cursor, end)), fileOffset + start, length);
        }
      } else if (type === 'tIME' && length >= 7) {
        addField('PNG', '修改时间 (UTC)', `${view.getUint16(start, false)}-${String(bytes[start + 2]).padStart(2,'0')}-${String(bytes[start + 3]).padStart(2,'0')} ${String(bytes[start + 4]).padStart(2,'0')}:${String(bytes[start + 5]).padStart(2,'0')}:${String(bytes[start + 6]).padStart(2,'0')}`, fileOffset + start, 7);
      } else if (type === 'eXIf') parseTiff(bytes.subarray(start, end), fileOffset + start, 'PNG / EXIF');
      else if (['pHYs','sRGB','gAMA'].includes(type)) addField('PNG', names[type], `${length} 字节结构字段`, fileOffset + start, length);
      else if (type === 'IEND') { addField('PNG', '结束块', 'IEND', fileOffset + position, 12); break; }
      position = end + 4;
    }
    if (chunks >= 100000) warn('PNG 块数量超过扫描上限。');
  }

  function parseWebp(bytes, fileOffset = 0) {
    addField('WebP', '容器', 'RIFF / WEBP', fileOffset, 12);
    const declared = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(4, true) + 8;
    addField('WebP', 'RIFF 声明长度', `${declared.toLocaleString()} 字节`, fileOffset + 4, 4);
    if (declared !== bytes.length) warn('WebP RIFF 声明长度与当前可读字节数不同；文件可能被截断或包含后续数据。');
    let position = 12, chunks = 0;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    while (position + 8 <= Math.min(bytes.length, declared) && chunks++ < 100000) {
      const type = latin1(bytes.subarray(position, position + 4)), length = view.getUint32(position + 4, true), start = position + 8;
      if (length > bytes.length - start) { warn(`WebP ${type} 块超出可读范围。`); break; }
      if (type === 'VP8X' && length >= 10) {
        addField('WebP / VP8X', '画布宽度', 1 + bytes[start + 4] + (bytes[start + 5] << 8) + (bytes[start + 6] << 16), fileOffset + start + 4, 3);
        addField('WebP / VP8X', '画布高度', 1 + bytes[start + 7] + (bytes[start + 8] << 8) + (bytes[start + 9] << 16), fileOffset + start + 7, 3);
      } else if (type === 'EXIF') parseTiff(bytes.subarray(start, start + length), fileOffset + start, 'WebP / EXIF');
      else if (type === 'XMP ' && length) {
        const text = decodeText(bytes.subarray(start, start + length));
        addField('WebP / XMP', '原始描述文本', text, fileOffset + start, length);
        extractXmp(text, fileOffset + start);
      } else if (type === 'ICCP') addField('WebP', 'ICC 色彩配置', `${length.toLocaleString()} 字节配置数据`, fileOffset + start, length);
      position = start + length + (length & 1);
    }
  }

  function extractXmp(text, offset) {
    const tags = [['dc:creator','创建者'],['dc:description','描述'],['dc:title','标题'],['xmp:CreateDate','创建时间'],['xmp:ModifyDate','修改时间'],['xmp:CreatorTool','创建工具'],['photoshop:DateCreated','拍摄时间']];
    for (const [tag, label] of tags) {
      const match = text.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i'));
      if (match) addField('XMP', label, match[1].replace(/<[^>]*>/g, ' ').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').trim(), offset, match[0].length);
    }
  }

  function decodePdfValue(value) {
    if (value.startsWith('<') && value.endsWith('>')) {
      const hex = value.slice(1, -1).replace(/\s/g, '');
      if (!/^[\da-f]*$/i.test(hex) || hex.length % 2) return value;
      const bytes = Uint8Array.from(hex.match(/../g) || [], pair => parseInt(pair, 16));
      if (bytes[0] === 0xfe && bytes[1] === 0xff) {
        let text = ''; for (let i = 2; i + 1 < bytes.length; i += 2) text += String.fromCharCode(bytes[i] * 256 + bytes[i + 1]);
        return text;
      }
      return decodeText(bytes);
    }
    if (!value.startsWith('(') || !value.endsWith(')')) return value;
    const source = value.slice(1, -1); let output = '', depth = 0;
    for (let i = 0; i < source.length; i++) {
      const char = source[i];
      if (char === '\\') {
        const next = source[++i];
        if (next === 'n') output += '\n'; else if (next === 'r') output += '\r'; else if (next === 't') output += '\t'; else if (next === '\n' || next === '\r') { if (next === '\r' && source[i + 1] === '\n') i++; }
        else if (/[0-7]/.test(next || '')) { let octal = next; for (let j = 0; j < 2 && /[0-7]/.test(source[i + 1] || ''); j++) octal += source[++i]; output += String.fromCharCode(parseInt(octal, 8)); }
        else output += next || '';
      } else if (char === '(') { depth++; output += char; }
      else if (char === ')' && depth > 0) { depth--; output += char; }
      else output += char;
    }
    return output;
  }

  function parsePdf(bytes, fileOffset = 0) {
    const text = latin1(bytes);
    const version = text.match(/^%PDF-(\d\.\d)/);
    addField('PDF', '版本', version ? version[1] : '未识别', fileOffset, 8);
    const infoReference = text.match(/\/Info\s+(\d+)\s+\d+\s+R/);
    let dictionary = '', dictionaryOffset = 0;
    if (infoReference) {
      const object = new RegExp(`(?:^|\\s)${infoReference[1]}\\s+\\d+\\s+obj([\\s\\S]*?)endobj`).exec(text);
      if (object) { dictionary = object[1]; dictionaryOffset = object.index + object[0].indexOf(object[1]); }
    }
    if (!dictionary) {
      const inline = /\/Info\s*<<(.*?)>>/s.exec(text);
      if (inline) { dictionary = inline[1]; dictionaryOffset = inline.index + inline[0].indexOf(inline[1]); }
    }
    const map = { Title:'标题',Author:'作者',Subject:'主题',Keywords:'关键词',Creator:'创建程序',Producer:'PDF 生成程序',CreationDate:'创建日期',ModDate:'修改日期',Trapped:'陷印标记' };
    if (dictionary) {
      for (const [key, label] of Object.entries(map)) {
        const match = new RegExp(`/${key}\\s*(\\((?:\\\\.|[^\\)])*\\)|<[^>]*>|\\w+)`).exec(dictionary);
        if (match) addField('PDF / Info', label, decodePdfValue(match[1]), fileOffset + dictionaryOffset + match.index, match[0].length);
      }
    } else warn('未找到可直接读取的 PDF Info 字典；字典可能位于压缩对象流、文件范围外或加密数据中。');
    const xmp = /<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/i.exec(text);
    if (xmp) { addField('PDF / XMP', '原始描述文本', xmp[0], fileOffset + xmp.index, xmp[0].length); extractXmp(xmp[0], fileOffset + xmp.index); }
  }

  function parseWav(bytes, fileOffset = 0) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    addField('WAV', '容器', 'RIFF / WAVE', fileOffset, 12);
    let position = 12, chunks = 0;
    const infoTags = { INAM:'标题',IART:'艺术家',ICRD:'日期',ICMT:'注释',ICOP:'版权',ISFT:'编码软件',IGNR:'流派',IENG:'工程师',ISBJ:'主题' };
    while (position + 8 <= bytes.length && chunks++ < 100000) {
      const type = latin1(bytes.subarray(position, position + 4)), length = view.getUint32(position + 4, true), start = position + 8;
      if (length > bytes.length - start) { warn(`WAV ${type} 块长度超出可读范围。`); break; }
      if (type === 'fmt ' && length >= 16) {
        const codec = view.getUint16(start, true), channels = view.getUint16(start + 2, true), rate = view.getUint32(start + 4, true), byteRate = view.getUint32(start + 8, true), bits = view.getUint16(start + 14, true);
        addField('WAV / fmt', '编码格式', codec === 1 ? 'PCM' : `格式码 ${codec}`, fileOffset + start, 2);
        addField('WAV / fmt', '声道数', channels, fileOffset + start + 2, 2);
        addField('WAV / fmt', '采样率', `${rate} Hz`, fileOffset + start + 4, 4);
        addField('WAV / fmt', '字节率', `${byteRate} byte/s`, fileOffset + start + 8, 4);
        addField('WAV / fmt', '位深', `${bits} bit`, fileOffset + start + 14, 2);
      } else if (type === 'data') addField('WAV', '音频数据长度', `${length.toLocaleString()} 字节`, fileOffset + position, length + 8);
      else if (type === 'LIST' && length >= 4 && latin1(bytes.subarray(start, start + 4)) === 'INFO') {
        let cursor = start + 4;
        while (cursor + 8 <= start + length) {
          const tag = latin1(bytes.subarray(cursor, cursor + 4)), size = view.getUint32(cursor + 4, true);
          if (size > start + length - cursor - 8) { warn('WAV LIST/INFO 子块长度超出范围。'); break; }
          if (infoTags[tag]) addField('WAV / INFO', infoTags[tag], latin1(bytes.subarray(cursor + 8, cursor + 8 + size)), fileOffset + cursor + 8, size);
          cursor += 8 + size + (size & 1);
        }
      }
      position = start + length + (length & 1);
    }
  }

  function parseFile(bytes, file) {
    fields.length = 0; warnings.length = 0;
    const prefix = latin1(bytes.subarray(0, Math.min(bytes.length, 16)));
    let format = '未知';
    if (bytes[0] === 0xff && bytes[1] === 0xd8) { format = 'JPEG'; parseJpeg(bytes); }
    else if (prefix.startsWith('II*\0') || prefix.startsWith('MM\0*')) { format = 'TIFF'; parseTiff(bytes, 0, 'TIFF'); }
    else if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 && bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a) { format = 'PNG'; parsePng(bytes); }
    else if (prefix.startsWith('RIFF') && prefix.slice(8, 12) === 'WEBP') { format = 'WebP'; parseWebp(bytes); }
    else if (prefix.startsWith('RIFF') && prefix.slice(8, 12) === 'WAVE') { format = 'WAV'; parseWav(bytes); }
    else if (prefix.startsWith('%PDF-')) { format = 'PDF'; parsePdf(bytes); }
    else warn('当前仅支持 JPEG、TIFF、PNG、WebP、PDF 与 RIFF/WAV；扩展名不会作为格式判定依据。');
    return format;
  }

  function render(format) {
    $('#format').textContent = format;
    $('#field-count').textContent = fields.length.toLocaleString();
    rows.replaceChildren();
    for (const field of fields) {
      const row = document.createElement('tr');
      const sourceRange = `${hexOffset(field.offset)} · ${field.length === null || field.length === undefined ? '长度未知' : `${field.length.toLocaleString()} 字节`}`;
      for (const value of [field.category, field.name, field.value, sourceRange]) {
        const cell = document.createElement('td'); cell.textContent = value; row.appendChild(cell);
      }
      rows.appendChild(row);
    }
    $('#empty-results').hidden = fields.length > 0;
    const warningPanel = $('#warnings-panel');
    warningPanel.hidden = warnings.length === 0;
    const list = $('#warnings'); list.replaceChildren();
    for (const message of warnings) { const item = document.createElement('li'); item.textContent = message; list.appendChild(item); }
    resultPanel.hidden = false;
  }

  input.addEventListener('change', async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    $('#file-info').textContent = `${file.name} · ${file.size.toLocaleString()} 字节 · ${file.type || 'MIME 类型未知'}`;
    resultPanel.hidden = true;
    if (file.size > MAX_FILE_SIZE) {
      status.className = 'status error';
      status.textContent = `文件超过 128 MiB 上限（${file.size.toLocaleString()} 字节），未读取。`;
      return;
    }
    status.className = 'status is-loading';
    status.textContent = '正在读取和解析文件…';
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const format = parseFile(bytes, file);
      render(format);
      status.className = `status ${format === '未知' ? 'warning' : 'success'}`;
      status.textContent = format === '未知' ? '格式不在当前支持范围内；原文件保持不变。' : `已完成本地读取，显示 ${fields.length.toLocaleString()} 个字段。原文件保持不变。`;
    } catch (error) {
      status.className = 'status error';
      status.textContent = `解析失败：${error.message || error}`;
    }
  });
})();
