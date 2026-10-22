const $ = function (selector) { return document.querySelector(selector); };
let run = null;

function workerMain() {
  const md5 = function (bytes) {
    const len = bytes.length;
    const buf = new Uint8Array(((len + 8 >>> 6) + 1) * 64);
    buf.set(bytes);
    buf[len] = 128;
    const bit = len * 8;
    for (let i = 0; i < 8; i++) buf[buf.length - 8 + i] = Math.floor(bit / Math.pow(2, 8 * i)) & 255;
    let a0 = 0x67452301 | 0, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476 | 0;
    const shifts = [7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21];
    const k = Array.from({length:64}, function (_, i) { return Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0; });
    for (let off = 0; off < buf.length; off += 64) {
      const m = new Int32Array(16);
      for (let i = 0; i < 16; i++) { const p = off + i * 4; m[i] = buf[p] | buf[p+1] << 8 | buf[p+2] << 16 | buf[p+3] << 24; }
      let a = a0, b = b0, c = c0, d = d0;
      for (let i = 0; i < 64; i++) {
        let f, g, shift;
        if (i < 16) { f = (b & c) | (~b & d); g = i; shift = shifts[i % 4]; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; shift = shifts[4 + i % 4]; }
        else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; shift = shifts[8 + i % 4]; }
        else { f = c ^ (b | ~d); g = (7 * i) % 16; shift = shifts[12 + i % 4]; }
        const x = (a + f + k[i] + m[g]) | 0;
        a = d; d = c; c = b; b = (b + ((x << shift) | (x >>> (32 - shift)))) | 0;
      }
      a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
    }
    return [a0,b0,c0,d0].map(function (n) {
      return [n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255].map(function (v) { return v.toString(16).padStart(2, '0'); }).join('');
    }).join('');
  };
  let bcryptTargets = [];
  let pbkdf2Targets = [];
  onmessage = async function (event) {
    const item = event.data;
    if (item.type === 'init') { bcryptTargets = item.bcryptTargets; pbkdf2Targets = item.pbkdf2Targets; return; }
    const bytes = new TextEncoder().encode(item.text);
    const hashes = {};
    const bcryptMatches = [];
    const pbkdf2Matches = [];
    for (const algorithm of item.algorithms) {
      if (algorithm === 'BCRYPT') {
        for (const target of bcryptTargets) {
          try { const marker = String.fromCharCode(36); const normalized = target.slice(0,4) === marker + '2y' + marker ? marker + '2b' + marker + target.slice(4) : target; if (dcodeIO.bcrypt.compareSync(item.text, normalized)) bcryptMatches.push(target); } catch (_) {}
        }
      } else if (algorithm === 'PBKDF2-SHA256') {
        for (const target of pbkdf2Targets) {
          const parts = target.split('$');
          const rounds = Number(parts[1]), salt = parts[2], expected = parts[3];
          try {
            const key = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveBits']);
            const bits = await crypto.subtle.deriveBits({name:'PBKDF2', hash:'SHA-256', salt:new TextEncoder().encode(salt), iterations:rounds}, key, 256);
            const actual = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(bits))));
            if (actual === expected) pbkdf2Matches.push(target);
          } catch (_) {}
        }
      } else if (algorithm === 'MD5') hashes.MD5 = md5(bytes);
      else {
        const digest = await crypto.subtle.digest(algorithm, bytes);
        hashes[algorithm] = Array.from(new Uint8Array(digest), function (b) { return b.toString(16).padStart(2, '0'); }).join('');
      }
    }
    postMessage({text:item.text, fileName:item.fileName, lineNo:item.lineNo, hashes:hashes, bcryptMatches:bcryptMatches, pbkdf2Matches:pbkdf2Matches});
  };
}

class Pool {
  constructor(n, targets, algorithms, onMatch) {
    this.n = n; this.targets = targets; this.algorithms = algorithms; this.onMatch = onMatch;
    this.workers = []; this.busy = []; this.queue = []; this.active = 0; this.waiters = []; this.total = 0; this.closed = false; this.error = null;
    const source = window.bcryptWorkerSource + '\n(' + workerMain.toString() + ')()';
    const url = URL.createObjectURL(new Blob([source], {type:'text/javascript'}));
    try {
      for (let i = 0; i < n; i++) {
        const worker = new Worker(url);
        this.workers.push(worker); this.busy.push(false);
        worker.postMessage({type:'init', bcryptTargets:Array.from(targets).filter(isBcryptHash), pbkdf2Targets:Array.from(targets).filter(isPBKDF2Hash)});
        worker.onmessage = (event) => {
          this.busy[i] = false; this.active--;
          const result = event.data; this.total++;
          for (const hash of Object.values(result.hashes).concat(result.bcryptMatches, result.pbkdf2Matches)) {
            if (this.targets.has(hash)) this.onMatch(hash, result.text, result.fileName, result.lineNo);
          }
          this.dispatch(); this.wake();
        };
        worker.onerror = () => { this.error = new Error('哈希 Worker 出错。请确认浏览器支持 Web Crypto，并重试。'); this.close(); };
      }
    } catch (error) {
      this.close();
      throw new Error('当前浏览器无法从本地 HTML 创建 Worker。请使用最新版 Chrome 或 Edge 打开。');
    } finally { URL.revokeObjectURL(url); }
  }
  wake() { for (const resolve of this.waiters.splice(0)) resolve(); }
  async slot() { while (this.active >= this.n && !this.closed) await new Promise((resolve) => this.waiters.push(resolve)); }
  submit(item) { if (!this.closed) { this.queue.push(item); this.dispatch(); } }
  dispatch() {
    if (this.closed) return;
    for (let i = 0; i < this.workers.length && this.queue.length; i++) {
      if (this.busy[i]) continue;
      this.busy[i] = true; this.active++; this.workers[i].postMessage(this.queue.shift());
    }
  }
  async finish() { while ((this.active || this.queue.length) && !this.closed) await new Promise((resolve) => this.waiters.push(resolve)); }
  close() { this.closed = true; for (const worker of this.workers) worker.terminate(); this.workers = []; this.busy = []; this.active = 0; this.queue = []; this.wake(); }
}

function dictionaryFiles() {
  return Array.from($('#folder').files).concat(Array.from($('#files').files))
    .filter((file) => /\.txt$/i.test(file.name) && !/^README(?:\..*)?$/i.test(file.name))
    .sort((a,b) => (a.webkitRelativePath || a.name).localeCompare(b.webkitRelativePath || b.name, undefined, {numeric:true,sensitivity:'base'}));
}
function showDictionaryFiles() {
  const files = dictionaryFiles(), box = $('#dictionary-list');
  box.replaceChildren();
  const heading = document.createElement('h3'); heading.textContent = '已读取字典（' + files.length + '）'; box.appendChild(heading);
  if (!files.length) { const empty = document.createElement('div'); empty.className = 'empty'; empty.textContent = '尚未选择 TXT 字典'; box.appendChild(empty); return; }
  const list = document.createElement('ul');
  files.forEach((file) => { const item = document.createElement('li'); item.textContent = file.webkitRelativePath || file.name; list.appendChild(item); });
  box.appendChild(list);
}
document.querySelectorAll('[data-pick]').forEach((button) => button.addEventListener('click', () => $('#' + button.dataset.pick).click()));

const HASH_ALGORITHMS = {32:'MD5',40:'SHA-1',64:'SHA-256',96:'SHA-384',128:'SHA-512'};
function isBcryptHash(hash) { return /^\$2[aby]\$(?:0[4-9]|[12]\d|3[01])\$[./A-Za-z0-9]{53}$/.test(hash); }
function isPBKDF2Hash(hash) { return /^pbkdf2_sha256\$[1-9]\d{0,8}\$[^$]+\$[A-Za-z0-9+/]+=*$/.test(hash); }
function detectAlgorithm(hash) {
  if (isBcryptHash(hash)) return 'BCRYPT';
  if (isPBKDF2Hash(hash)) return 'PBKDF2-SHA256';
  return /^[a-f\d]+$/i.test(hash) ? HASH_ALGORITHMS[hash.length] || null : null;
}
function parsedTargets() {
  const map = new Map(), bad = [], selected = $('#algorithm').value;
  $('#hashes').value.split(/\r?\n/).forEach((line, index) => {
    const raw = line.trim(); if (!raw) return;
    const detected = detectAlgorithm(raw), algorithm = selected === 'AUTO' ? detected : selected;
    if (!detected || algorithm !== detected) { bad.push(index + 1); return; }
    const hash = (algorithm === 'BCRYPT' || algorithm === 'PBKDF2-SHA256') ? raw : raw.toLowerCase();
    if (!map.has(hash)) map.set(hash, algorithm);
  });
  return {map:map, bad:bad, algorithms:Array.from(new Set(map.values()))};
}
function formatDuration(ms) {
  const seconds = ms / 1000;
  return seconds < 60 ? seconds.toFixed(2) + ' 秒' : Math.floor(seconds / 60) + ' 分 ' + (seconds % 60).toFixed(2) + ' 秒';
}
function renderResults(targets, matches, elapsed) {
  return '本次匹配耗时：' + formatDuration(elapsed) + '\n\n' +
    Array.from(targets.keys()).map((hash) => {
      const match = matches.get(hash);
      return ['密文（' + targets.get(hash) + '）：' + hash, '明文：' + (match ? match.text : '（未找到）'), '匹配结果：' + (match ? '已匹配' : '未匹配')]
        .concat(match ? ['字典文件：' + match.fileName, '字典行号：' + match.lineNo] : []).join('\n');
    }).join('\n\n──────────────\n\n');
}
async function* linesOf(file) {
  if (file.stream) {
    const reader = file.stream().getReader(), decoder = new TextDecoder('utf-8'); let pending = '';
    while (true) {
      const result = await reader.read();
      pending += decoder.decode(result.value || new Uint8Array(), {stream:!result.done});
      const parts = pending.split(/\r?\n/); pending = parts.pop();
      for (const line of parts) yield line;
      if (result.done) break;
    }
    if (pending) yield pending;
  } else {
    const text = await file.text();
    for (const line of text.split(/\r?\n/)) yield line;
  }
}
$('#folder').addEventListener('change', () => {
  const count = dictionaryFiles().length; showDictionaryFiles();
  $('#status').textContent = count ? '已读取 ' + count + ' 个 TXT 字典文件（README 已跳过）。点击“开始匹配”处理。' : '所选目录中没有可读取的 TXT 字典。';
});
$('#files').addEventListener('change', () => {
  const count = dictionaryFiles().length; showDictionaryFiles();
  $('#status').textContent = count ? '已读取 ' + count + ' 个 TXT 字典文件。' : '没有找到可读取的 TXT 字典文件。';
});

$('#start').addEventListener('click', async () => {
  if (run) return;
  const parsed = parsedTargets(), targets = parsed.map, bad = parsed.bad, algorithms = parsed.algorithms;
  if (!targets.size) {
    $('#status').className = 'status error';
    $('#status').textContent = bad.length ? '没有符合所选算法的有效哈希（MD5、SHA-1、SHA-256、SHA-384、SHA-512、bcrypt、PBKDF2-SHA256）。无效行：' + bad.join(', ') : '请先输入至少一个哈希值。';
    return;
  }
  const files = dictionaryFiles();
  if (!files.length) { $('#status').className = 'status error'; $('#status').textContent = '请先选择 dicts 文件夹或 TXT 字典文件。'; return; }
  const threadCount = Math.min(8, Math.max(1, Number($('#threads').value) || 1));
  const matches = new Map(), startedAt = performance.now();
  $('#results').textContent = renderResults(targets, matches, 0);
  $('#start').disabled = true; $('#stop').disabled = false; $('#progress').style.width = '0%';
  run = {stop:false, pool:null};
  try {
    const pool = new Pool(threadCount, new Set(targets.keys()), algorithms, (hash,text,fileName,lineNo) => {
      if (!matches.has(hash)) { matches.set(hash, {text:text,fileName:fileName,lineNo:lineNo}); $('#results').textContent = renderResults(targets, matches, performance.now() - startedAt); }
    });
    run.pool = pool;
    let count = 0;
    for (let fileIndex = 0; fileIndex < files.length && !run.stop && matches.size < targets.size; fileIndex++) {
      const file = files[fileIndex], fileName = file.webkitRelativePath || file.name;
      $('#status').className = 'status';
      $('#status').textContent = '正在处理 ' + (fileIndex + 1) + '/' + files.length + '：' + fileName + '\n并行 Worker：' + threadCount + ' · 当前文件候选词：' + count;
      let lineNo = 0;
      for await (const raw of linesOf(file)) {
        lineNo++;
        if (run.stop || matches.size === targets.size) break;
        await pool.slot();
        pool.submit({text:raw.replace(/\r$/, ''),fileName:fileName,lineNo:lineNo,algorithms:algorithms});
        count++;
        if (count % 500 === 0) $('#status').textContent = '正在处理 ' + (fileIndex + 1) + '/' + files.length + '：' + fileName + '\n已读取候选词：' + count + ' · 匹配：' + matches.size + '/' + targets.size + ' · 已耗时：' + formatDuration(performance.now() - startedAt);
      }
      await pool.finish();
      if (pool.error) throw pool.error;
      $('#progress').style.width = Math.round((fileIndex + 1) / files.length * 100) + '%';
    }
    pool.close();
    if (matches.size === targets.size) $('#progress').style.width = '100%';
    const elapsed = performance.now() - startedAt;
    $('#results').textContent = renderResults(targets, matches, elapsed);
    $('#status').className = 'status ' + (run.stop ? 'warning' : 'success');
    $('#status').textContent = run.stop
      ? '已停止。已计算 ' + pool.total + ' 个候选词，命中 ' + matches.size + '/' + targets.size + '，耗时 ' + formatDuration(elapsed) + '。'
      : '处理完成：' + files.length + ' 个字典文件，共计算 ' + pool.total + ' 个候选词，命中 ' + matches.size + '/' + targets.size + '，耗时 ' + formatDuration(elapsed) + '。';
  } catch (error) {
    $('#status').className = 'status error'; $('#status').textContent = '处理失败：' + error.message; run.pool && run.pool.close();
  } finally {
    run = null; $('#start').disabled = false; $('#stop').disabled = true;
  }
});
$('#stop').addEventListener('click', () => {
  if (run) { run.stop = true; if (run.pool) run.pool.close(); $('#stop').disabled = true; $('#status').className = 'status warning'; $('#status').textContent = '正在停止…'; }
});
$('#clear').addEventListener('click', () => { $('#results').textContent = '尚无结果'; $('#progress').style.width = '0%'; });
$('#copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('#results').textContent); } catch (_) {}
  $('#status').className = 'status success'; $('#status').textContent = '结果已复制。';
});
