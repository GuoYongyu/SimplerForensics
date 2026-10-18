(() => {
  const $ = selector => document.querySelector(selector);
  const fileInput = $('#file');
  const viewer = $('#viewer');
  const offsetInput = $('#offset');
  const pageSizeInput = $('#page-size');
  const output = $('#hex-output');
  const fileInfo = $('#file-info');
  const status = $('#status');
  const searchResults = $('#search-results');
  const progress = $('#search-progress');
  const exportStatus = $('#export-status');
  let selectedFile = null;
  let pageStart = 0;
  let searchRun = 0;

  const formatSize = size => `${size.toLocaleString('zh-CN')} 字节`;
  const setStatus = (element, message, kind = '') => {
    element.hidden = false;
    element.className = `status${kind ? ` ${kind}` : ''}`;
    element.textContent = message;
  };
  const parseOffset = value => {
    const input = value.trim();
    if (!/^(?:0x[\da-f]+|\d+)$/i.test(input)) return NaN;
    try { return Number(BigInt(input)); } catch { return NaN; }
  };

  function renderBytes(bytes, start) {
    const rows = [];
    for (let row = 0; row < bytes.length; row += 16) {
      const line = bytes.subarray(row, row + 16);
      const address = (start + row).toString(16).toUpperCase().padStart(8, '0');
      const hex = Array.from(line, value => value.toString(16).toUpperCase().padStart(2, '0'));
      const left = hex.slice(0, 8).join(' ').padEnd(23, ' ');
      const right = hex.slice(8).join(' ');
      const ascii = Array.from(line, value => value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : '·').join('');
      rows.push(`${address}  ${left} ${right.padEnd(23, ' ')}  ${ascii}`);
    }
    output.textContent = rows.join('\n');
  }

  async function showPage(start = pageStart) {
    if (!selectedFile) return;
    const pageSize = Number(pageSizeInput.value);
    pageStart = Math.min(Math.max(0, start), Math.max(0, selectedFile.size - 1));
    pageStart = Math.floor(pageStart / 16) * 16;
    offsetInput.value = String(pageStart);
    const bytes = new Uint8Array(await selectedFile.slice(pageStart, pageStart + pageSize).arrayBuffer());
    renderBytes(bytes, pageStart);
    $('#page-info').textContent = bytes.length
      ? `显示偏移 ${pageStart.toLocaleString()}–${(pageStart + bytes.length - 1).toLocaleString()}，共 ${bytes.length.toLocaleString()} 字节。`
      : '文件为空，没有可显示的字节。';
    $('#previous').disabled = pageStart === 0;
    $('#next').disabled = pageStart + bytes.length >= selectedFile.size;
  }

  function parseSearchPattern() {
    const value = $('#search-value').value.trim();
    if (!value) throw new Error('请输入要搜索的内容。');
    if ($('#search-mode').value === 'text') return new TextEncoder().encode(value);
    if (!/^[\da-f\s,:-]+$/i.test(value)) throw new Error('十六进制搜索只接受 0–9、A–F 和常见分隔符。');
    const compact = value.replace(/0x/gi, '').replace(/[\s,:-]/g, '');
    if (!compact || compact.length % 2) throw new Error('十六进制内容必须由完整字节组成，例如 50 4B 03 04。');
    return Uint8Array.from(compact.match(/../g), pair => parseInt(pair, 16));
  }

  function findPattern(bytes, pattern, from = 0) {
    if (pattern.length > bytes.length) return -1;
    const shifts = new Uint32Array(256).fill(pattern.length);
    for (let i = 0; i < pattern.length - 1; i++) shifts[pattern[i]] = pattern.length - 1 - i;
    let position = Math.max(0, from);
    while (position <= bytes.length - pattern.length) {
      let i = pattern.length - 1;
      while (i >= 0 && bytes[position + i] === pattern[i]) i--;
      if (i < 0) return position;
      position += shifts[bytes[position + pattern.length - 1]] || 1;
    }
    return -1;
  }

  async function searchFile() {
    if (!selectedFile) return;
    let pattern;
    try { pattern = parseSearchPattern(); }
    catch (error) { setStatus(searchResults, error.message, 'error'); return; }
    if (pattern.length > 65536) { setStatus(searchResults, '搜索内容不能超过 64 KiB。', 'error'); return; }
    const run = ++searchRun;
    const chunkSize = 1024 * 1024;
    const matches = [];
    let carry = new Uint8Array(0);
    let scanned = 0;
    $('#search').disabled = true;
    $('#cancel-search').disabled = false;
    progress.hidden = false;
    progress.max = Math.max(1, selectedFile.size);
    progress.value = 0;
    setStatus(searchResults, '正在分块搜索…');
    try {
      while (scanned < selectedFile.size) {
        if (run !== searchRun) return;
        const chunk = new Uint8Array(await selectedFile.slice(scanned, scanned + chunkSize).arrayBuffer());
        const combined = new Uint8Array(carry.length + chunk.length);
        combined.set(carry);
        combined.set(chunk, carry.length);
        const baseOffset = scanned - carry.length;
        let from = 0;
        while (matches.length < 100) {
          const found = findPattern(combined, pattern, from);
          if (found < 0) break;
          const absolute = baseOffset + found;
          if (absolute >= 0 && absolute + pattern.length <= scanned + chunk.length) matches.push(absolute);
          from = found + 1;
        }
        scanned += chunk.length;
        carry = combined.slice(Math.max(0, combined.length - pattern.length + 1));
        progress.value = scanned;
        await new Promise(resolve => setTimeout(resolve, 0));
        if (matches.length >= 100) break;
      }
      if (run !== searchRun) return;
      const finished = scanned >= selectedFile.size;
      const rows = matches.map(position => `十进制 ${position.toLocaleString()} · 十六进制 0x${position.toString(16).toUpperCase()}`);
      setStatus(searchResults, `${finished ? '搜索完成' : '已达到 100 个结果上限'}；已检查 ${scanned.toLocaleString()} / ${selectedFile.size.toLocaleString()} 字节，找到 ${matches.length} 处${rows.length ? `：\n${rows.join('\n')}` : '。'}`, matches.length ? 'success' : 'warning');
    } catch (error) {
      if (run === searchRun) setStatus(searchResults, `搜索失败：${error.message || error}`, 'error');
    } finally {
      if (run === searchRun) {
        $('#search').disabled = false;
        $('#cancel-search').disabled = true;
      }
    }
  }

  fileInput.addEventListener('change', event => {
    const file = event.target.files?.[0];
    if (!file) return;
    searchRun++;
    $('#search').disabled = false;
    $('#cancel-search').disabled = true;
    progress.hidden = true;
    selectedFile = file;
    pageStart = 0;
    viewer.hidden = false;
    searchResults.hidden = true;
    exportStatus.hidden = true;
    fileInfo.textContent = `${file.name} · ${formatSize(file.size)} · ${file.type || 'MIME 类型未知'}`;
    setStatus(status, '文件已选择。内容通过 File.slice 分页读取，不会一次载入整个文件。', 'success');
    showPage().catch(error => setStatus(status, `读取失败：${error.message || error}`, 'error'));
  });
  $('#go').addEventListener('click', () => {
    const start = parseOffset(offsetInput.value);
    if (!Number.isSafeInteger(start) || start < 0 || start >= selectedFile?.size) {
      setStatus(status, '偏移必须是文件范围内的非负安全整数。', 'error');
      return;
    }
    showPage(start).catch(error => setStatus(status, `读取失败：${error.message || error}`, 'error'));
  });
  offsetInput.addEventListener('keydown', event => { if (event.key === 'Enter') $('#go').click(); });
  $('#previous').addEventListener('click', () => showPage(Math.max(0, pageStart - Number(pageSizeInput.value))));
  $('#next').addEventListener('click', () => showPage(pageStart + Number(pageSizeInput.value)));
  pageSizeInput.addEventListener('change', () => showPage(pageStart));
  $('#search').addEventListener('click', searchFile);
  $('#cancel-search').addEventListener('click', () => {
    searchRun++;
    $('#search').disabled = false;
    $('#cancel-search').disabled = true;
    progress.hidden = true;
    setStatus(searchResults, '搜索已取消。', 'warning');
  });
  $('#use-page').addEventListener('click', () => {
    $('#range-start').value = pageStart;
    $('#range-length').value = Math.min(Number(pageSizeInput.value), Math.max(0, selectedFile.size - pageStart));
  });
  $('#export-range').addEventListener('click', () => {
    const start = Number($('#range-start').value);
    const length = Number($('#range-length').value);
    const maxLength = 64 * 1024 * 1024;
    if (!selectedFile || !Number.isSafeInteger(start) || !Number.isSafeInteger(length) || start < 0 || length < 1 || start + length > selectedFile.size) {
      setStatus(exportStatus, '起始偏移和长度必须落在文件范围内，长度至少为 1 字节。', 'error');
      return;
    }
    if (length > maxLength) { setStatus(exportStatus, '单次导出不能超过 64 MiB。', 'error'); return; }
    const blob = selectedFile.slice(start, start + length, 'application/octet-stream');
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${selectedFile.name}.offset-${start}-length-${length}.bin`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setStatus(exportStatus, `已导出 ${length.toLocaleString()} 字节的派生文件；原文件未修改。`, 'success');
  });
})();
