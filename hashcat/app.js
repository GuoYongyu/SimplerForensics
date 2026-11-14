/*
 * HashCat workbench UI.
 *
 * Candidate generation happens on the main thread in bounded batches; hashing
 * happens in a small pool of Blob workers so the page stays responsive without
 * requiring a local server or any network request.
 */
(() => {
  'use strict';

  const C = window.HashcatCore;
  if (!C) return;

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  // Hard cap for deterministic mask/regex spaces. Soft limits only ask for
  // confirmation and keep very large hybrid runs from starting by accident.
  const MAX_CANDIDATES = 500000000;
  const SOFT_LIMIT = 50000000;
  const HYBRID_SOFT_LIMIT = 5000000;
  const ATTACK_LABELS = { mask: '掩码攻击', dict: '字典攻击', hybrid: '混合攻击', regex: '正则约束' };

  const state = {
    attack: 'mask',
    blocks: [{ type: 'lower', count: 4 }, { type: 'digits', count: 2 }],
    maskSource: 'builder',
    rawMask: '?l?l?l?l?d?d',
    customSets: ['', '', '', ''],
    regex: { pattern: '[A-Z][a-z]{2}\\d{2}', maxLength: 16, parsed: null, info: null },
    rules: { base: 'none', trim: false, reverse: false, duplicate: false, leet: false, prefix: '', suffix: '', appendChars: '', prependChars: '', years: false },
    hybridDirection: 'suffix'
  };

  let run = null;
  let lastRun = null;
  let hashTimer = null;
  let regexTimer = null;
  let workerUrl = null;

  /* ------------------------------------------------------------------ *
   * Worker: hashing only. The worker source is assembled from the pure
   * core functions so file:// pages do not need a separate worker file.
   * ------------------------------------------------------------------ */

  function hashcatWorkerMain() {
    'use strict';
    var unsalted = new Map();
    var saltedGroups = [];
    var bcryptTargets = [];
    var netntlmTargets = [];
    var dcc2Targets = [];
    var modes = [];
    var encoder = new TextEncoder();

    function bytesToHex(buffer) {
      var bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
      var out = '';
      for (var i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
      return out;
    }

    function shaAlgorithm(algorithm) {
      return algorithm === 'SHA1' ? 'SHA-1' : algorithm === 'SHA256' ? 'SHA-256' : 'SHA-512';
    }

    self.onmessage = async function (event) {
      var message = event.data;
      try {
        if (message.type === 'init') {
          unsalted = new Map();
          saltedGroups = [];
          bcryptTargets = [];
          netntlmTargets = [];
          dcc2Targets = [];
          modes = [];
          (message.targets || []).forEach(function (target) {
            if (!target || !target.key) return;
            if (target.kind === 'bcrypt') {
              bcryptTargets.push({ key: target.key, hash: target.hash });
              return;
            }
            if (target.kind === 'netntlmv2') {
              netntlmTargets.push({
                key: target.key,
                proof: target.proof,
                challengeBytes: hexToBytes(target.challenge),
                blobBytes: hexToBytes(target.blob),
                userDomainBytes: utf16leBytes(target.username.toUpperCase() + target.domain)
              });
              return;
            }
            if (target.kind === 'dcc2') {
              dcc2Targets.push({
                key: target.key,
                hash: target.hash,
                iterations: target.iterations,
                saltBytes: utf16leBytes(target.username.toLowerCase())
              });
              return;
            }
            if (target.kind === 'salted') {
              var groupKey = target.mode + '|' + target.saltPosition + '|' + target.salt;
              var group = saltedGroups.find(function (item) { return item.groupKey === groupKey; });
              if (!group) {
                group = {
                  groupKey: groupKey,
                  mode: target.mode,
                  algorithm: target.algorithm,
                  salt: target.salt,
                  saltPosition: target.saltPosition,
                  hashes: new Map()
                };
                saltedGroups.push(group);
              }
              group.hashes.set(target.hash, target.key);
              return;
            }
            if (!unsalted.has(target.mode)) unsalted.set(target.mode, new Map());
            unsalted.get(target.mode).set(target.hash, target.key);
          });
          modes = Array.from(unsalted.keys());
          return;
        }
        if (message.type !== 'batch') return;
        var candidates = message.candidates || [];
        var matches = [];
        for (var index = 0; index < candidates.length; index++) {
          var candidate = candidates[index];
          var bytes = null;
          var ntHashBytes = null;

          for (var mi = 0; mi < modes.length; mi++) {
            var mode = modes[mi];
            var hash;
            if (mode === 'MD5') {
              hash = md5(encoder.encode(candidate));
            } else if (mode === 'NTLM') {
              hash = ntlm(candidate);
            } else {
              if (!bytes) bytes = encoder.encode(candidate);
              var digest = await crypto.subtle.digest(shaAlgorithm(mode), bytes);
              hash = bytesToHex(digest);
            }
            var unsaltedKey = unsalted.get(mode).get(hash);
            if (unsaltedKey) matches.push({ key: unsaltedKey, mode: mode, candidate: candidate });
          }

          for (var si = 0; si < saltedGroups.length; si++) {
            var salted = saltedGroups[si];
            var saltedText = salted.saltPosition === 'before' ? salted.salt + candidate : candidate + salted.salt;
            var saltedBytes = encoder.encode(saltedText);
            var saltedHash = salted.algorithm === 'MD5'
              ? md5(saltedBytes)
              : bytesToHex(await crypto.subtle.digest(shaAlgorithm(salted.algorithm), saltedBytes));
            var saltedKey = salted.hashes.get(saltedHash);
            if (saltedKey) matches.push({ key: saltedKey, mode: salted.mode, candidate: candidate });
          }

          for (var bi = 0; bi < bcryptTargets.length; bi++) {
            var bcryptTarget = bcryptTargets[bi];
            try {
              var marker = String.fromCharCode(36);
              var normalized = bcryptTarget.hash.slice(0, 4) === marker + '2y' + marker
                ? marker + '2b' + marker + bcryptTarget.hash.slice(4)
                : bcryptTarget.hash;
              if (dcodeIO.bcrypt.compareSync(candidate, normalized)) {
                matches.push({ key: bcryptTarget.key, mode: 'BCRYPT', candidate: candidate });
              }
            } catch (_) { /* malformed target or candidate */ }
          }

          if (netntlmTargets.length || dcc2Targets.length) {
            ntHashBytes = hexToBytes(md4(utf16leBytes(candidate)));
          }
          for (var ni = 0; ni < netntlmTargets.length; ni++) {
            var netntlm = netntlmTargets[ni];
            var ntlmv2Key = hmacMd5(ntHashBytes, netntlm.userDomainBytes);
            var proof = bytesToHex(hmacMd5(ntlmv2Key, concatBytes(netntlm.challengeBytes, netntlm.blobBytes)));
            if (proof === netntlm.proof) {
              matches.push({ key: netntlm.key, mode: 'NETNTLMv2', candidate: candidate });
            }
          }
          for (var di = 0; di < dcc2Targets.length; di++) {
            var dcc2 = dcc2Targets[di];
            var dcc2Secret = hexToBytes(md4(concatBytes(ntHashBytes, dcc2.saltBytes)));
            var imported = await crypto.subtle.importKey('raw', dcc2Secret, 'PBKDF2', false, ['deriveBits']);
            var bits = await crypto.subtle.deriveBits({
              name: 'PBKDF2',
              hash: 'SHA-1',
              salt: dcc2.saltBytes,
              iterations: dcc2.iterations
            }, imported, 128);
            if (bytesToHex(new Uint8Array(bits)) === dcc2.hash) {
              matches.push({ key: dcc2.key, mode: 'DCC2', candidate: candidate });
            }
          }
        }
        self.postMessage({ type: 'done', seq: message.seq, processed: candidates.length, matches: matches });
      } catch (error) {
        self.postMessage({ type: 'error', seq: message && message.seq, message: String((error && error.message) || error) });
      }
    };
  }

  function getWorkerUrl() {
    if (workerUrl) return workerUrl;
    const core = window.HashcatCore;
    const source = [
      window.bcryptWorkerSource || '',
      'const md5 = ' + core.md5.toString() + ';',
      'const md4 = ' + core.md4.toString() + ';',
      'const ntlm = ' + core.ntlm.toString() + ';',
      'const hexToBytes = ' + core.hexToBytes.toString() + ';',
      'const utf16leBytes = ' + core.utf16leBytes.toString() + ';',
      'const concatBytes = ' + core.concatBytes.toString() + ';',
      'const hmacMd5 = ' + core.hmacMd5.toString() + ';',
      '(' + hashcatWorkerMain.toString() + ')();'
    ].join('\n');
    workerUrl = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
    return workerUrl;
  }

  class HashPool {
    constructor(threadCount, targets, callbacks) {
      this.n = threadCount;
      this.targets = targets;
      this.onMatch = callbacks.onMatch;
      this.onError = callbacks.onError;
      this.workers = [];
      this.busy = [];
      this.queue = [];
      this.active = 0;
      this.completed = 0;
      this.seq = 0;
      this.closed = false;
      this.error = null;
      this.waiters = [];

      const initialTargets = targets.map((target) => Object.assign({}, target));
      const url = getWorkerUrl();
      try {
        for (let i = 0; i < threadCount; i++) {
          const worker = new Worker(url);
          worker.onmessage = (event) => this.handleMessage(event, i);
          worker.onerror = (event) => this.fail('哈希 Worker 出错' + (event && event.message ? '：' + event.message : '。请确认浏览器支持 Web Crypto，并重试。'));
          worker.onmessageerror = () => this.fail('哈希 Worker 消息无法解析。');
          this.workers.push(worker);
          this.busy.push(false);
          worker.postMessage({ type: 'init', targets: initialTargets });
        }
      } catch (error) {
        this.close();
        throw new Error('当前浏览器无法从本地页面创建 Worker。请使用最新版 Chrome 或 Edge，或通过启动脚本打开。');
      }
    }

    get queueLength() { return this.queue.length; }

    wake() {
      for (const resolve of this.waiters.splice(0)) resolve();
    }

    fail(message) {
      if (this.error || this.closed) return;
      this.error = new Error(message);
      if (this.onError) this.onError(this.error);
      this.close();
    }

    waitForRoom() {
      const limit = Math.max(4, this.n * 4);
      if (this.closed || this.error || this.queue.length < limit) return Promise.resolve();
      return new Promise((resolve) => this.waiters.push(resolve));
    }

    submit(candidates) {
      if (this.closed || this.error) return false;
      this.queue.push({ type: 'batch', seq: this.seq++, candidates: candidates });
      this.dispatch();
      return true;
    }

    dispatch() {
      if (this.closed || this.error) return;
      for (let i = 0; i < this.workers.length && this.queue.length; i++) {
        if (this.busy[i]) continue;
        this.busy[i] = true;
        this.active++;
        this.workers[i].postMessage(this.queue.shift());
      }
    }

    handleMessage(event, index) {
      if (this.closed) return;
      if (event.data && event.data.type === 'error') { this.fail('哈希 Worker 处理失败：' + event.data.message); return; }
      this.busy[index] = false;
      this.active--;
      this.completed += event.data.processed || 0;
      for (const match of event.data.matches || []) this.onMatch(match);
      this.dispatch();
      this.wake();
    }

    async finish() {
      while ((this.active || this.queue.length) && !this.closed) {
        await new Promise((resolve) => this.waiters.push(resolve));
      }
      if (this.error) throw this.error;
    }

    close() {
      this.closed = true;
      for (const worker of this.workers) worker.terminate();
      this.workers = [];
      this.busy = [];
      this.queue = [];
      this.active = 0;
      this.wake();
    }
  }

  /* ------------------------------------------------------------------ *
   * Input readers
   * ------------------------------------------------------------------ */

  function readRules() {
    return {
      base: $('#rule-base').value,
      trim: $('#rule-trim').checked,
      reverse: $('#rule-reverse').checked,
      duplicate: $('#rule-duplicate').checked,
      leet: $('#rule-leet').checked,
      prefix: $('#rule-prefix').value,
      suffix: $('#rule-suffix').value,
      appendChars: $('#rule-append-chars').value,
      prependChars: $('#rule-prepend-chars').value,
      years: $('#rule-years').checked
    };
  }

  function readConstraints() {
    return C.normalizeConstraints({
      minLength: $('#constraint-min').value,
      maxLength: $('#constraint-max').value,
      requireLower: $('#constraint-lower').checked,
      requireUpper: $('#constraint-upper').checked,
      requireDigit: $('#constraint-digit').checked,
      requireSymbol: $('#constraint-symbol').checked,
      contains: $('#constraint-contains').value.split(/\r?\n/),
      containsMode: $('#constraint-contains-mode').value,
      ignoreCase: $('#constraint-ignore-case').checked,
      requireAny: $('#constraint-require-any').value,
      requireAll: $('#constraint-require-all').value,
      exclude: $('#constraint-exclude').value
    });
  }

  function currentMask() {
    return state.maskSource === 'raw' ? state.rawMask : C.maskFromBlocks(state.blocks, state.customSets);
  }

  function currentCompiledMask() {
    return C.compileMask(currentMask(), state.customSets);
  }

  function dictionaryFiles() {
    return Array.from($('#dict-folder').files).concat(Array.from($('#dict-files').files))
      .filter((file) => /\.txt$/i.test(file.name) && !/^README(?:\..*)?$/i.test(file.name))
      .sort((a, b) => (a.webkitRelativePath || a.name).localeCompare(b.webkitRelativePath || b.name, undefined, { numeric: true, sensitivity: 'base' }));
  }

  function showDictionaryFiles() {
    const files = dictionaryFiles();
    const box = $('#dict-list');
    box.replaceChildren();
    const heading = document.createElement('h3');
    heading.textContent = '已读取字典（' + files.length + '）';
    box.appendChild(heading);
    if (!files.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = '尚未选择 TXT 字典';
      box.appendChild(empty);
    } else {
      const list = document.createElement('ul');
      files.forEach((file) => {
        const item = document.createElement('li');
        item.textContent = file.webkitRelativePath || file.name;
        list.appendChild(item);
      });
      box.appendChild(list);
    }
    updateRunSummary();
    updateRuleEstimate();
  }

  function detectTextEncoding(bytes, done) {
    if (bytes.length >= 2 && bytes[0] === 0xFF && bytes[1] === 0xFE) return { encoding: 'utf-16le', offset: 2 };
    if (bytes.length >= 2 && bytes[0] === 0xFE && bytes[1] === 0xFF) return { encoding: 'utf-16be', offset: 2 };
    if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) return { encoding: 'utf-8', offset: 3 };
    if (bytes.length >= 4 && bytes[1] === 0 && bytes[3] === 0) return { encoding: 'utf-16le', offset: 0 };
    if (bytes.length >= 4 && bytes[0] === 0 && bytes[2] === 0) return { encoding: 'utf-16be', offset: 0 };
    if (done || bytes.length >= 4) return { encoding: 'utf-8', offset: 0 };
    return null;
  }

  function decodeTextBuffer(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const detected = detectTextEncoding(bytes, true) || { encoding: 'utf-8', offset: 0 };
    return new TextDecoder(detected.encoding).decode(bytes.subarray(detected.offset));
  }

  async function* linesOf(file) {
    if (file.stream) {
      const reader = file.stream().getReader();
      let decoder = null;
      let header = new Uint8Array(0);
      let pending = '';
      while (true) {
        const result = await reader.read();
        let chunk = result.value ? new Uint8Array(result.value) : new Uint8Array(0);
        if (!decoder) {
          header = C.concatBytes(header, chunk);
          const detected = detectTextEncoding(header, result.done);
          if (!detected) continue;
          decoder = new TextDecoder(detected.encoding);
          chunk = header.subarray(detected.offset);
          header = new Uint8Array(0);
        }
        pending += decoder.decode(chunk, { stream: !result.done });
        const parts = pending.split(/\r?\n/);
        pending = parts.pop();
        for (const line of parts) yield line;
        if (result.done) break;
      }
      if (pending) yield pending;
    } else {
      const text = decodeTextBuffer(await file.arrayBuffer());
      for (const line of text.split(/\r?\n/)) yield line;
    }
  }

  /* ------------------------------------------------------------------ *
   * Rendering: mask builder
   * ------------------------------------------------------------------ */

  function renderBlocks() {
    const list = $('#block-list');
    list.replaceChildren();
    if (!state.blocks.length) {
      const empty = document.createElement('div');
      empty.className = 'hc-empty';
      empty.textContent = '尚未添加块。点击“添加块”组合字符类型，或切换到“直接输入掩码”。';
      list.appendChild(empty);
      return;
    }
    state.blocks.forEach((block, index) => {
      const row = document.createElement('div');
      row.className = 'hc-block';
      row.dataset.index = String(index);

      const head = document.createElement('div');
      head.className = 'hc-block-head';
      const badge = document.createElement('span');
      badge.className = 'hc-block-index';
      badge.textContent = String(index + 1).padStart(2, '0');
      const select = document.createElement('select');
      select.className = 'hc-block-type';
      select.setAttribute('aria-label', '第 ' + (index + 1) + ' 个块的字符类型');
      Object.entries(C.BLOCK_LABELS).forEach(([value, label]) => {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = label + (C.BLOCK_TOKENS[value] ? '  ?' + C.BLOCK_TOKENS[value] : '');
        select.appendChild(option);
      });
      select.value = block.type;
      select.addEventListener('change', () => {
        block.type = select.value;
        if (block.type === 'literal') {
          if (typeof block.text !== 'string') block.text = '';
        } else if (!block.count) {
          block.count = 1;
        }
        renderBlocks();
        updateMaskPreview();
      });

      const actions = document.createElement('div');
      actions.className = 'hc-block-actions';
      [['up', '↑', '上移'], ['down', '↓', '下移'], ['remove', '×', '删除']].forEach(([action, text, label]) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'hc-icon-btn';
        button.dataset.action = action;
        button.title = label;
        button.setAttribute('aria-label', label + '第 ' + (index + 1) + ' 个块');
        button.textContent = text;
        actions.appendChild(button);
      });

      head.append(badge, select, actions);
      row.appendChild(head);

      const body = document.createElement('div');
      body.className = 'hc-block-body';
      if (block.type === 'literal') {
        const input = document.createElement('input');
        input.className = 'field hc-block-text';
        input.type = 'text';
        input.value = block.text || '';
        input.placeholder = '字面文本，例如 2024 或 admin';
        input.setAttribute('aria-label', '第 ' + (index + 1) + ' 个块的字面文本');
        input.addEventListener('input', () => {
          block.text = input.value;
          updateMaskPreview();
        });
        body.appendChild(input);
      } else {
        const label = document.createElement('label');
        label.className = 'hc-block-count';
        const caption = document.createElement('span');
        caption.textContent = '重复次数';
        const input = document.createElement('input');
        input.className = 'field';
        input.type = 'number';
        input.min = '1';
        input.max = '64';
        input.value = String(block.count || 1);
        input.setAttribute('aria-label', '第 ' + (index + 1) + ' 个块的重复次数');
        input.addEventListener('input', () => {
          block.count = C.clampInt(input.value, 1, 64, 1);
          updateMaskPreview();
        });
        label.append(caption, input);
        body.appendChild(label);
        const preview = document.createElement('p');
        preview.className = 'hint hc-block-hint';
        preview.textContent = blockHint(block);
        body.appendChild(preview);
      }
      row.appendChild(body);
      list.appendChild(row);
    });
  }

  function blockHint(block) {
    if (block.type === 'literal') return '';
    if (block.type.startsWith('custom')) {
      const index = Number(block.type.slice(-1)) - 1;
      const expanded = C.expandCustomSet(state.customSets[index] || '');
      return expanded.ok ? '该块共 ' + Array.from(expanded.chars).length + ' 个可选字符。' : '自定义字符集尚未设置完整。';
    }
    const map = {
      lower: C.LOWER, upper: C.UPPER, digits: C.DIGITS, symbols: C.SYMBOLS,
      all: C.ALL, hexLower: C.HEX_LOWER, hexUpper: C.HEX_UPPER
    };
    return '该块共 ' + (map[block.type] || '').length + ' 个可选字符。';
  }

  function updateCustomSummary() {
    const parts = [];
    for (let i = 0; i < 4; i++) {
      const value = state.customSets[i];
      if (!value) continue;
      const expanded = C.expandCustomSet(value);
      parts.push('?' + (i + 1) + ' = ' + (expanded.ok ? Array.from(expanded.chars).length + ' 个字符' : '错误：' + expanded.error));
    }
    $('#custom-summary').textContent = parts.length ? parts.join(' · ') : '可输入普通字符或 HashCat 字符集语法（如 ?l?d）。字面问号写 ??。';
    $('#custom-summary').className = 'hint';
  }

  function updateMaskPreview() {
    const compiled = currentCompiledMask();
    const error = $('#mask-error');
    updateCustomSummary();
    updateRunSummary();
    updateRuleEstimate();
    updateCommand();
    if (!compiled.ok) {
      $('#mask-preview').textContent = '—';
      $('#mask-count').textContent = '—';
      $('#mask-count').className = 'hc-count';
      $('#mask-length').textContent = '—';
      error.hidden = false;
      error.textContent = compiled.error;
      return;
    }
    $('#mask-preview').textContent = compiled.mask;
    $('#mask-count').textContent = C.formatCount(compiled.keyspace) + ' 个候选';
    $('#mask-count').className = compiled.keyspace > BigInt(SOFT_LIMIT) ? 'hc-count is-warning' : 'hc-count';
    $('#mask-length').textContent = compiled.length + ' 个位置';
    error.hidden = true;
    error.textContent = '';
  }

  /* ------------------------------------------------------------------ *
   * Rendering: regex
   * ------------------------------------------------------------------ */

  function setRegexStatus(message, className) {
    const status = $('#regex-status');
    status.className = 'status ' + (className || '');
    status.textContent = message;
  }

  function updateRegexPreview() {
    const pattern = $('#regex-pattern').value.trim();
    const maxLength = C.clampInt($('#regex-max-length').value, 1, 64, 16);
    state.regex.pattern = pattern;
    state.regex.maxLength = maxLength;
    if (!pattern) {
      state.regex.parsed = null;
      state.regex.info = null;
      setRegexStatus('输入一个正则表达式，或点击下方模板。', '');
      $('#regex-count').textContent = '—';
      $('#regex-count').className = 'hc-count';
      $('#regex-length-range').textContent = '—';
      $('#regex-samples').replaceChildren();
      updateRunSummary();
      updateCommand();
      return;
    }
    const parsed = C.parseRegex(pattern);
    state.regex.parsed = parsed;
    if (!parsed.ok) {
      state.regex.info = null;
      setRegexStatus('正则无法解析：' + parsed.error, 'error');
      $('#regex-count').textContent = '—';
      $('#regex-count').className = 'hc-count';
      $('#regex-length-range').textContent = '—';
      $('#regex-samples').replaceChildren();
      updateRunSummary();
      updateCommand();
      return;
    }
    const info = C.countRegex(parsed.ast, maxLength, C.COUNT_CAP);
    state.regex.info = info;
    if (!info.total || info.minLength < 0) {
      setRegexStatus('当前正则没有匹配任何长度不超过 ' + maxLength + ' 的候选。请增大“最大长度”或修改模式。', 'error');
      $('#regex-count').textContent = '0';
      $('#regex-count').className = 'hc-count';
      $('#regex-length-range').textContent = '—';
      $('#regex-samples').replaceChildren();
      updateRunSummary();
      updateCommand();
      return;
    }
    const constraints = readConstraints();
    let testable = info.total;
    if (constraints.minLength !== null || constraints.maxLength !== null) {
      const from = Math.max(0, constraints.minLength === null ? 0 : constraints.minLength);
      const to = Math.min(maxLength, constraints.maxLength === null ? maxLength : constraints.maxLength);
      let sum = 0;
      for (let i = from; i <= to; i++) sum += info.byLength[i] || 0;
      testable = Math.min(sum, C.COUNT_CAP);
    }
    $('#regex-count').textContent = C.formatCount(testable) + ' 个候选' + (info.capped ? '（估算已封顶）' : '');
    $('#regex-count').className = testable > SOFT_LIMIT ? 'hc-count is-warning' : 'hc-count';
    $('#regex-length-range').textContent = info.minLength === info.maxLength ? info.minLength + ' 个字符' : info.minLength + '–' + info.maxLength + ' 个字符';

    const samples = C.sampleRegex(parsed.ast, maxLength, 12);
    const box = $('#regex-samples');
    box.replaceChildren();
    if (!samples.length) {
      const empty = document.createElement('span');
      empty.className = 'hc-sample-empty';
      empty.textContent = '没有可显示的示例。';
      box.appendChild(empty);
    } else {
      samples.forEach((sample) => {
        const code = document.createElement('code');
        code.className = 'hc-sample-chip';
        code.textContent = sample === '' ? '（空字符串）' : sample;
        box.appendChild(code);
      });
    }

    const warnings = Array.from(new Set(parsed.warnings));
    if (parsed.unbounded) warnings.push('* / + 的最大重复按“最大长度 ' + maxLength + '”截断');
    if (info.capped) warnings.push('候选数超过估算上限，仅显示封顶值');
    const message = '可生成 ' + C.formatCount(info.total) + ' 个候选；长度 ' +
      (info.minLength === info.maxLength ? info.minLength : info.minLength + '–' + info.maxLength) + '。' +
      (warnings.length ? ' ' + warnings.join('；') + '。' : '');
    if (!testable) setRegexStatus('当前长度约束下没有候选；请调整长度范围或正则表达式。', 'error');
    else setRegexStatus(message, testable > SOFT_LIMIT || info.capped ? 'warning' : 'success');
    updateRunSummary();
    updateCommand();
  }

  function insertAtCursor(textarea, text, cursorOffset) {
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    textarea.value = textarea.value.slice(0, start) + text + textarea.value.slice(end);
    const position = start + (cursorOffset === undefined ? text.length : cursorOffset);
    textarea.setSelectionRange(position, position);
    textarea.focus();
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
  }

  /* ------------------------------------------------------------------ *
   * Rendering: summary, rules and command
   * ------------------------------------------------------------------ */

  function updateSaltUi() {
    const mode = $('#hash-mode').value;
    const definition = C.MODES[mode];
    const salted = !!(definition && definition.kind === 'salted');
    $('#salt-row').hidden = !salted;
    let hint;
    if (!definition) {
      hint = '自动检测：无盐的 32/40/64/128 位十六进制、bcrypt、NetNTLMv2 和 $DCC2$ 会自动识别。带盐的固定 Salt 模式需要手动选择，并写 hash:salt 或填写全局 Salt。';
    } else if (definition.kind === 'salted') {
      hint = definition.label + '：每行写 hash:salt，或使用全局 Salt；Salt 位置由该模式决定（-m ' + definition.hashcat + '）。';
    } else if (definition.kind === 'netntlmv2') {
      hint = 'NetNTLMv2 行格式：user::domain:serverChallenge:NTProofStr:blob；也会自动识别这种格式。';
    } else if (definition.kind === 'dcc2') {
      hint = 'DCC2 行格式：$DCC2$10240#user#hash；Windows Vista+ 的域缓存凭据。浏览器 PBKDF2 验证较慢。';
    } else if (definition.kind === 'bcrypt') {
      hint = 'bcrypt：使用 $2a$ / $2b$ / $2y$ 格式；bcrypt 成本越高越慢。';
    } else {
      hint = definition.label + '：无盐模式，每行只写哈希。Windows 的 NTLM 也是无盐哈希；32 位十六进制在自动模式下默认按 MD5 处理。';
    }
    $('#hash-format-hint').textContent = hint;
  }

  function updateHashSummary() {
    const selected = $('#hash-mode').value;
    const parsed = C.parseHashLines($('#hashes').value, selected, $('#global-salt').value);
    const summary = $('#hash-summary');
    if (!parsed.targets.size && !parsed.invalid.length) {
      summary.className = 'status';
      summary.textContent = '尚未输入哈希。可粘贴一个哈希，或点击右上角“填入示例”。';
      updateCommand();
      return;
    }
    const parts = Object.entries(parsed.counts).map(([mode, count]) => ((C.MODES[mode] || {}).label || mode) + ' × ' + count);
    let message = '识别到 ' + parsed.targets.size + ' 个哈希' + (parts.length ? '：' + parts.join('、') : '') + '。';
    if (parsed.ambiguous32) message += ' 32 位十六进制在自动模式下按 MD5 处理；如需 NTLM，请手动选择 NTLM。';
    if (parsed.invalid.length) {
      const lines = parsed.invalid.slice(0, 4).map((item) => '第 ' + item.line + ' 行').join('、');
      message += ' 忽略 ' + parsed.invalid.length + ' 行无效输入（' + lines + (parsed.invalid.length > 4 ? ' 等' : '') + '）。';
      summary.className = 'status warning';
    } else {
      summary.className = 'status success';
    }
    summary.textContent = message;
    updateCommand();
  }

  function updateConstraintSummary() {
    const constraints = readConstraints();
    const parts = C.constraintSummary(constraints);
    const summary = $('#constraint-summary');
    if (!parts.length) {
      summary.className = 'hint';
      summary.textContent = '未启用特征约束：将尝试攻击模式生成的全部候选。';
    } else {
      summary.className = 'status warning';
      summary.textContent = '当前约束：' + parts.join('；') + '。约束会逐个过滤候选，候选空间显示的值是过滤前的估算。';
    }
  }

  function updateRuleEstimate() {
    const rules = readRules();
    const estimate = C.variantEstimate(rules);
    let message = estimate > 1 ? '每个字典词约生成 ' + estimate + ' 个候选。' : '每个字典词生成 1 个候选。';
    if (state.attack === 'hybrid') {
      const compiled = currentCompiledMask();
      if (compiled.ok) message += ' 再与 ' + C.formatCount(compiled.keyspace) + ' 个掩码组合。';
    }
    if (rules.leet) message += ' 1337 替换会同时生成原始与替换变体。';
    if (rules.years) message += ' 年份范围 2020–2026。';
    $('#rule-estimate').textContent = message;
  }

  function updateRunSummary() {
    const parts = ['攻击：' + ATTACK_LABELS[state.attack]];
    if (state.attack === 'mask' || state.attack === 'hybrid') {
      const compiled = currentCompiledMask();
      parts.push(compiled.ok ? '掩码 ' + compiled.mask + ' · ' + C.formatCount(compiled.keyspace) + ' 个候选' : '掩码无效');
    }
    if (state.attack === 'dict' || state.attack === 'hybrid') {
      parts.push('字典 ' + dictionaryFiles().length + ' 个文件');
    }
    if (state.attack === 'regex') {
      parts.push(state.regex.info ? '正则 ' + C.formatCount(state.regex.info.total) + ' 个候选' : '正则需要解析');
    }
    const constraints = readConstraints();
    const constraintParts = C.constraintSummary(constraints);
    if (constraintParts.length) parts.push('约束 ' + constraintParts.length + ' 项');
    $('#run-summary').textContent = parts.join(' · ');
  }

  function updateCommand() {
    const parsed = C.parseHashLines($('#hashes').value, $('#hash-mode').value, $('#global-salt').value);
    const modes = Array.from(new Set(Array.from(parsed.targets.values()).map((target) => target.mode)));
    const compiled = currentCompiledMask();
    const command = C.hashcatCommand({
      attack: state.attack,
      modes: modes,
      mask: compiled.ok ? compiled.mask : '',
      customSets: state.customSets,
      customUsed: compiled.ok ? compiled.customUsed : [],
      direction: $('#hybrid-direction').value,
      rules: readRules(),
      constraints: readConstraints()
    });
    let text = command || 'hashcat ...';
    if (!modes.length) text = '# 先输入有效哈希，下方会自动填入 -m 模式值\n' + text;
    if ((state.attack === 'mask' || state.attack === 'hybrid') && !compiled.ok) text = '# 当前掩码无效：' + compiled.error + '\n' + text;
    if (state.attack === 'regex' && (!state.regex.parsed || !state.regex.parsed.ok)) text = '# 当前正则尚未成功解析\n' + text;
    if (state.attack === 'regex') text += '\n# 本页不会执行上方的 hashcat 命令。';
    $('#hashcat-command').textContent = text;
  }

  function setAttack(attack) {
    state.attack = attack;
    $$('input[name="attack"]').forEach((input) => { if (input.value === attack) input.checked = true; });
    $('#dict-section').hidden = !(attack === 'dict' || attack === 'hybrid');
    $('#mask-section').hidden = !(attack === 'mask' || attack === 'hybrid');
    $('#pane-regex').hidden = attack !== 'regex';
    $('#hybrid-options').hidden = attack !== 'hybrid';
    $('#mask-section-title').textContent = attack === 'hybrid' ? '混合攻击的掩码' : '可视化掩码构建器';
    $('#mask-section-note').textContent = attack === 'hybrid'
      ? '混合攻击先应用字典规则，再把掩码拼接到词前或词后；方向在下方“字典与规则”中选择。'
      : '每个块代表一组位置。编译后的掩码与 HashCat -a 3 的写法一致。';
    if (attack === 'regex') updateRegexPreview();
    updateRunSummary();
    updateCommand();
  }

  /* ------------------------------------------------------------------ *
   * Results and stats
   * ------------------------------------------------------------------ */

  function countFound(resultMap) {
    let found = 0;
    for (const result of resultMap.values()) if (result.found) found++;
    return found;
  }

  function renderResults(runState) {
    const box = $('#results');
    box.replaceChildren();
    if (!runState) {
      const empty = document.createElement('div');
      empty.className = 'hc-empty';
      empty.textContent = '尚无结果。配置攻击方式并点击“开始破解”。';
      box.appendChild(empty);
      return;
    }
    for (const result of runState.results.values()) {
      const card = document.createElement('article');
      card.className = 'hc-result' + (result.found ? ' is-found' : '') + (runState.finished && !result.found ? ' is-missing' : '');
      const head = document.createElement('div');
      head.className = 'hc-result-head';
      const code = document.createElement('code');
      code.className = 'hc-result-hash';
      code.textContent = result.target ? result.target.display : result.key;
      const mode = document.createElement('span');
      mode.className = 'chip';
      mode.textContent = (C.MODES[result.mode] || {}).label || result.mode;
      const status = document.createElement('span');
      status.className = 'hc-result-status';
      status.textContent = result.found ? '已命中' : runState.finished ? '未找到' : '等待中';
      head.append(code, mode, status);
      card.appendChild(head);
      if (result.found) {
        const plain = document.createElement('div');
        plain.className = 'hc-result-plain';
        const label = document.createElement('span');
        label.textContent = '明文';
        const value = document.createElement('strong');
        value.textContent = result.plaintext;
        plain.append(label, value);
        card.appendChild(plain);
      }
      const meta = document.createElement('div');
      meta.className = 'hc-result-meta';
      meta.textContent = 'HashCat 模式 -m ' + ((C.MODES[result.mode] || {}).hashcat ?? '?');
      card.appendChild(meta);
      box.appendChild(card);
    }
  }

  function updateStats(runState, final) {
    if (!runState) return;
    const elapsed = Math.max(1, performance.now() - runState.startedAt);
    const completed = runState.pool ? runState.pool.completed : 0;
    const speed = completed / elapsed * 1000;
    const found = countFound(runState.results);
    const targetCount = runState.targets.length;
    const total = runState.total;
    const hasFilters = C.hasConstraints(runState.constraints);
    $('#stat-tested').textContent = C.formatCount(completed);
    $('#stat-speed').textContent = C.formatCount(Math.round(speed)) + ' 个/秒';
    $('#stat-elapsed').textContent = C.formatDuration(elapsed);
    $('#stat-matched').textContent = found + ' / ' + targetCount;
    if (total && total > 0) {
      let remaining = Math.max(0, total - completed) / Math.max(1, speed) * 1000;
      $('#stat-eta').textContent = (hasFilters ? '≤ ' : '') + C.formatDuration(remaining);
      const percent = final && found === targetCount ? 100 : Math.min(100, runState.generated / total * 100);
      $('#progress').style.width = percent.toFixed(1) + '%';
      $('#progress-wrap').classList.remove('is-indeterminate');
    } else {
      $('#stat-eta').textContent = final ? '已完成' : '未知';
      if (final) {
        $('#progress-wrap').classList.remove('is-indeterminate');
        $('#progress').style.width = '100%';
      } else {
        $('#progress-wrap').classList.add('is-indeterminate');
        $('#progress').style.width = '100%';
      }
    }
    if (runState.finished || runState.stop) return;
    const now = performance.now();
    if (runState.lastStatusAt && now - runState.lastStatusAt < 900) return;
    runState.lastStatusAt = now;
    const prefix = runState.currentFile ? ATTACK_LABELS[runState.attack] + ' · ' + runState.currentFile : ATTACK_LABELS[runState.attack];
    const generated = '已生成 ' + C.formatCount(runState.generated) + (total ? ' / ' + C.formatCount(total) : '');
    const tested = '已测试 ' + C.formatCount(completed);
    const matched = '命中 ' + found + '/' + targetCount;
    const rate = '速度 ' + C.formatCount(Math.round(speed)) + '/秒';
    const time = '已用时 ' + C.formatDuration(elapsed);
    $('#status').className = 'status is-loading';
    const spinner = document.createElement('span');
    spinner.className = 'analysis-spinner';
    const text = document.createElement('span');
    text.textContent = prefix + ' · ' + generated + ' · ' + tested + ' · ' + matched + ' · ' + rate + ' · ' + time;
    $('#status').replaceChildren(spinner, text);
  }

  function collectResultText(runState) {
    if (!runState) return '';
    const lines = ['HashCat 破解工作台结果', '时间：' + new Date().toLocaleString(), ''];
    for (const result of runState.results.values()) {
      lines.push('哈希（' + ((C.MODES[result.mode] || {}).label || result.mode) + '）：' + (result.target ? result.target.display : result.key));
      lines.push('状态：' + (result.found ? '已命中' : '未找到'));
      if (result.found) lines.push('明文：' + result.plaintext);
      lines.push('');
    }
    return lines.join('\n').trim();
  }

  function setRunning(running) {
    $('#start').disabled = running;
    $('#stop').disabled = !running;
    $('#start').textContent = running ? '破解进行中…' : '开始破解';
  }

  function finalizeRun(runState) {
    runState.finished = true;
    runState.elapsed = performance.now() - runState.startedAt;
    const found = countFound(runState.results);
    const total = runState.targets.length;
    const completed = runState.pool ? runState.pool.completed : 0;
    const status = $('#status');
    status.replaceChildren();
    if (runState.stop) {
      status.className = 'status warning';
      status.textContent = '已停止：命中 ' + found + '/' + total + '，已测试 ' + C.formatCount(completed) + ' 个候选，用时 ' + C.formatDuration(runState.elapsed) + '。';
    } else if (found === total) {
      status.className = 'status success';
      status.textContent = '全部命中：' + found + '/' + total + '，已测试 ' + C.formatCount(completed) + ' 个候选，用时 ' + C.formatDuration(runState.elapsed) + '。';
      $('#progress').style.width = '100%';
    } else {
      status.className = 'status warning';
      status.textContent = '处理完成：命中 ' + found + '/' + total + '，已测试 ' + C.formatCount(completed) + ' 个候选，用时 ' + C.formatDuration(runState.elapsed) + '。可调整掩码、正则或字典规则后重试。';
    }
    lastRun = runState;
    renderResults(runState);
    updateStats(runState, true);
  }

  function handleMatch(runState, match) {
    const result = runState.results.get(match.key);
    if (!result || result.found) return;
    result.found = true;
    result.plaintext = match.candidate;
    let all = true;
    for (const item of runState.results.values()) if (!item.found) { all = false; break; }
    if (all) {
      runState.foundAll = true;
      if (runState.pool) runState.pool.close();
    }
    renderResults(runState);
    updateStats(runState, false);
  }

  function stopped(runState) {
    return !run || run !== runState || runState.stop || runState.foundAll || !runState.pool || !!runState.pool.error;
  }

  async function sendBatch(runState, batch) {
    if (!batch.length) return true;
    while (!stopped(runState)) {
      const limit = Math.max(4, runState.pool.n * 4);
      if (runState.pool.queueLength < limit) break;
      await runState.pool.waitForRoom();
    }
    if (stopped(runState)) return false;
    return runState.pool.submit(batch);
  }

  function batchSizeFor(targets) {
    const modes = new Set(targets.map((target) => target.mode));
    if (modes.has('DCC2')) return 4;
    if (modes.has('BCRYPT')) return 24;
    if (modes.has('NETNTLMv2')) return 120;
    const usesSha = targets.some((target) => {
      const definition = C.MODES[target.mode];
      return definition && (definition.algorithm === 'SHA1' || definition.algorithm === 'SHA256' || definition.algorithm === 'SHA512');
    });
    return usesSha ? 400 : 1600;
  }

  function breathe() {
    return new Promise((resolve) => setTimeout(resolve, 0));
  }

  async function feedMask(runState) {
    const compiled = runState.mask;
    const keyspace = Number(compiled.keyspace);
    const chunk = 2000;
    let batch = [];
    for (let start = 0; start < keyspace && !stopped(runState); start += chunk) {
      const candidates = C.buildMaskBatch(compiled, start, chunk);
      for (const candidate of candidates) {
        runState.generated++;
        if (runState.generated % 25000 === 0) await breathe();
        if (!C.constraintsPass(candidate, runState.constraints)) continue;
        batch.push(candidate);
        if (batch.length >= runState.batchSize) {
          if (!await sendBatch(runState, batch)) return;
          batch = [];
        }
      }
    }
    if (batch.length && !stopped(runState)) await sendBatch(runState, batch);
  }

  async function feedRegex(runState) {
    const iterator = C.regexGenerator(runState.regex.ast, runState.regex.maxLength);
    let batch = [];
    for (const candidate of iterator) {
      if (stopped(runState)) return;
      runState.generated++;
      if (runState.generated % 25000 === 0) await breathe();
      if (!C.constraintsPass(candidate, runState.constraints)) continue;
      batch.push(candidate);
      if (batch.length >= runState.batchSize) {
        if (!await sendBatch(runState, batch)) return;
        batch = [];
      }
    }
    if (batch.length && !stopped(runState)) await sendBatch(runState, batch);
  }

  async function feedDictionary(runState, hybrid) {
    const files = runState.files;
    let batch = [];
    for (let fileIndex = 0; fileIndex < files.length && !stopped(runState); fileIndex++) {
      const file = files[fileIndex];
      runState.currentFile = file.webkitRelativePath || file.name;
      let lineNo = 0;
      for await (const raw of linesOf(file)) {
        lineNo++;
        if (stopped(runState)) break;
        const variants = C.variantsForWord(raw.replace(/^\uFEFF/, '').replace(/\r$/, ''), runState.rules);
        for (const variant of variants) {
          if (hybrid) {
            const keyspace = Number(runState.mask.keyspace);
            const chunk = 2000;
            for (let start = 0; start < keyspace && !stopped(runState); start += chunk) {
              for (const maskCandidate of C.buildMaskBatch(runState.mask, start, chunk)) {
                const candidate = runState.direction === 'prefix' ? maskCandidate + variant : variant + maskCandidate;
                runState.generated++;
                if (runState.generated % 25000 === 0) await breathe();
                if (!C.constraintsPass(candidate, runState.constraints)) continue;
                batch.push(candidate);
                if (batch.length >= runState.batchSize) {
                  if (!await sendBatch(runState, batch)) return;
                  batch = [];
                }
              }
            }
          } else {
            runState.generated++;
            if (runState.generated % 25000 === 0) await breathe();
            if (!C.constraintsPass(variant, runState.constraints)) continue;
            batch.push(variant);
            if (batch.length >= runState.batchSize) {
              if (!await sendBatch(runState, batch)) return;
              batch = [];
            }
          }
        }
      }
      if (stopped(runState)) break;
    }
    if (batch.length && !stopped(runState)) await sendBatch(runState, batch);
  }

  /* ------------------------------------------------------------------ *
   * Start/stop
   * ------------------------------------------------------------------ */

  function fail(message) {
    $('#status').className = 'status error';
    $('#status').textContent = message;
  }

  function maskConstraintIssue(compiled, constraints) {
    if (!compiled.ok) return null;
    const available = compiled.positions.map((position) => position.chars.join('')).join('');
    if (constraints.requireLower && !/[a-z]/.test(available)) return '掩码的字符集中没有小写字母，无法满足“至少 1 个小写字母”。';
    if (constraints.requireUpper && !/[A-Z]/.test(available)) return '掩码的字符集中没有大写字母，无法满足“至少 1 个大写字母”。';
    if (constraints.requireDigit && !/[0-9]/.test(available)) return '掩码的字符集中没有数字，无法满足“至少 1 个数字”。';
    if (constraints.requireSymbol && !Array.from(C.SYMBOLS).some((ch) => available.indexOf(ch) !== -1)) return '掩码的字符集中没有符号，无法满足“至少 1 个符号”。';
    for (const ch of constraints.requireAll) {
      if (available.indexOf(ch) === -1) return '掩码的字符集中不包含必须出现的字符“' + ch + '”。';
    }
    if (constraints.requireAny) {
      const any = Array.from(constraints.requireAny).some((ch) => available.indexOf(ch) !== -1);
      if (!any) return '掩码的字符集中不包含“必须包含任一字符”里的任何字符。';
    }
    if (constraints.exclude) {
      const trapped = compiled.positions.some((position) => Array.from(position.chars).every((ch) => constraints.exclude.indexOf(ch) !== -1));
      if (trapped) return '掩码的某个位置只包含被排除的字符，所有候选都会被过滤。';
    }
    return null;
  }

  async function startCrack() {
    if (run) return;
    const parsed = C.parseHashLines($('#hashes').value, $('#hash-mode').value, $('#global-salt').value);
    if (!parsed.targets.size) {
      fail(parsed.invalid.length ? '没有有效哈希。无效输入：' + parsed.invalid.map((item) => '第 ' + item.line + ' 行（' + item.reason + '）').join('；') : '请先输入至少一个哈希值。');
      return;
    }
    const parsedTargets = Array.from(parsed.targets.values());
    if (parsedTargets.some((target) => target.mode === 'BCRYPT') && !window.bcryptWorkerSource) {
      fail('bcrypt 验证组件未加载（ciphertext/bcrypt-source.js）。请确认文件存在后刷新页面。');
      return;
    }
    const constraints = readConstraints();
    const rules = readRules();
    const compiled = currentCompiledMask();
    const files = dictionaryFiles();
    const attack = state.attack;
    if (attack === 'mask' || attack === 'hybrid') {
      if (!compiled.ok) { fail('掩码无效：' + compiled.error); return; }
    }
    if (attack === 'mask') {
      if (constraints.minLength !== null && compiled.length < constraints.minLength) { fail('掩码长度 ' + compiled.length + ' 小于约束最小长度 ' + constraints.minLength + '，所有候选都会被过滤。'); return; }
      if (constraints.maxLength !== null && compiled.length > constraints.maxLength) { fail('掩码长度 ' + compiled.length + ' 大于约束最大长度 ' + constraints.maxLength + '，所有候选都会被过滤。'); return; }
      const issue = maskConstraintIssue(compiled, constraints);
      if (issue) { fail(issue); return; }
    }
    if (attack === 'dict' || attack === 'hybrid') {
      if (!files.length) { fail('请先选择要使用的 TXT 字典文件或字典目录。'); return; }
    }

    let total = null;
    let estimated = null;
    let regexState = null;
    if (attack === 'mask') {
      if (compiled.keyspace > BigInt(MAX_CANDIDATES)) {
        fail('候选空间为 ' + C.formatCount(compiled.keyspace) + '，超过浏览器模式的 ' + C.formatCount(MAX_CANDIDATES) + ' 个候选上限。请减少位数或缩小字符集。');
        return;
      }
      total = Number(compiled.keyspace);
      estimated = total;
    } else if (attack === 'regex') {
      updateRegexPreview();
      const parsedRegex = state.regex.parsed;
      const info = state.regex.info;
      if (!parsedRegex || !parsedRegex.ok || !info) { fail('正则表达式无效或尚未解析。请查看正则区域的状态提示。'); return; }
      if (info.capped || info.total > MAX_CANDIDATES) {
        fail('正则候选空间过大（' + C.formatCount(info.total) + '），超过浏览器模式的 ' + C.formatCount(MAX_CANDIDATES) + ' 个候选上限。请增加固定字符、缩小字符集或降低最大长度。');
        return;
      }
      let testable = info.total;
      if (constraints.minLength !== null || constraints.maxLength !== null) {
        const from = Math.max(0, constraints.minLength === null ? 0 : constraints.minLength);
        const to = Math.min(state.regex.maxLength, constraints.maxLength === null ? state.regex.maxLength : constraints.maxLength);
        let sum = 0;
        for (let i = from; i <= to; i++) sum += info.byLength[i] || 0;
        testable = sum;
      }
      if (!testable) { fail('当前正则与长度约束组合后没有候选，请调整正则或长度范围。'); return; }
      total = info.total;
      estimated = testable;
      regexState = { ast: parsedRegex.ast, maxLength: state.regex.maxLength };
    } else if (attack === 'hybrid') {
      if (compiled.keyspace > BigInt(MAX_CANDIDATES)) {
        fail('混合攻击的掩码空间为 ' + C.formatCount(compiled.keyspace) + '，超过浏览器模式的候选上限。请缩小掩码。');
        return;
      }
      if (compiled.keyspace > BigInt(HYBRID_SOFT_LIMIT)) {
        const ok = window.confirm('混合攻击的掩码部分有 ' + C.formatCount(compiled.keyspace) + ' 个候选；乘以字典词数后可能非常久。仍要继续吗？');
        if (!ok) return;
      }
      estimated = null;
    }

    if (estimated !== null && estimated > SOFT_LIMIT) {
      const ok = window.confirm('本次预计需要验证 ' + C.formatCount(estimated) + ' 个候选。浏览器版速度远低于 GPU HashCat，可能耗时较久。仍要继续吗？');
      if (!ok) return;
    }
    if (parsedTargets.some((target) => target.mode === 'BCRYPT') && estimated !== null && estimated > 20000) {
      const ok = window.confirm('目标包含 bcrypt。浏览器中的 bcrypt 验证非常慢，' + C.formatCount(estimated) + ' 个候选可能需要很久。仍要继续吗？');
      if (!ok) return;
    }
    if (parsedTargets.some((target) => target.mode === 'DCC2') && estimated !== null && estimated > 5000) {
      const ok = window.confirm('目标包含 Windows DCC2（MS-Cache v2），每个候选都要执行 PBKDF2-HMAC-SHA1。' + C.formatCount(estimated) + ' 个候选可能需要很久。仍要继续吗？');
      if (!ok) return;
    }

    const targets = parsedTargets;
    const results = new Map();
    targets.forEach((target) => results.set(target.key, { target: target, mode: target.mode, found: false, plaintext: null }));
    const threads = C.clampInt($('#threads').value, 1, 8, 4);
    const runState = {
      stop: false,
      foundAll: false,
      finished: false,
      attack: attack,
      targets: targets,
      results: results,
      constraints: constraints,
      rules: rules,
      mask: compiled.ok ? compiled : null,
      direction: $('#hybrid-direction').value,
      total: total,
      generated: 0,
      startedAt: performance.now(),
      currentFile: '',
      files: files,
      regex: regexState,
      batchSize: batchSizeFor(targets),
      pool: null,
      timer: null,
      lastStatusAt: 0
    };
    run = runState;
    lastRun = runState;
    renderResults(runState);
    setRunning(true);
    $('#progress').style.width = '0%';
    $('#progress-wrap').classList.remove('is-indeterminate');
    ['#stat-tested', '#stat-speed', '#stat-elapsed', '#stat-eta', '#stat-matched'].forEach((selector) => { $(selector).textContent = '—'; });
    $('#status').className = 'status is-loading';
    $('#status').replaceChildren();
    const spinner = document.createElement('span');
    spinner.className = 'analysis-spinner';
    const text = document.createElement('span');
    text.textContent = '正在启动 Worker 并准备候选…';
    $('#status').replaceChildren(spinner, text);
    try {
      runState.pool = new HashPool(threads, targets, {
        onMatch: (match) => handleMatch(runState, match),
        onError: (error) => {
          if (runState.finished) return;
          runState.error = error;
        }
      });
      runState.timer = setInterval(() => updateStats(runState, false), 250);
      if (attack === 'mask') await feedMask(runState);
      else if (attack === 'regex') await feedRegex(runState);
      else await feedDictionary(runState, attack === 'hybrid');

      if (!runState.stop && !runState.foundAll && runState.pool.error === null) await runState.pool.finish();
      if (runState.pool.error) throw runState.pool.error;
      finalizeRun(runState);
    } catch (error) {
      if (runState.pool) runState.pool.close();
      runState.finished = true;
      runState.elapsed = performance.now() - runState.startedAt;
      lastRun = runState;
      $('#status').className = 'status error';
      $('#status').textContent = '破解失败：' + error.message;
    } finally {
      if (runState.timer) clearInterval(runState.timer);
      if (runState.pool) runState.pool.close();
      runState.finished = true;
      run = null;
      setRunning(false);
      renderResults(runState);
    }
  }

  /* ------------------------------------------------------------------ *
   * Wiring
   * ------------------------------------------------------------------ */

  function clearConstraints() {
    ['#constraint-min', '#constraint-max', '#constraint-require-any', '#constraint-require-all', '#constraint-exclude', '#constraint-contains'].forEach((selector) => { $(selector).value = ''; });
    ['#constraint-lower', '#constraint-upper', '#constraint-digit', '#constraint-symbol', '#constraint-ignore-case'].forEach((selector) => { $(selector).checked = false; });
    $('#constraint-contains-mode').value = 'any';
    $('#constraint-contains-mode').dispatchEvent(new Event('change', { bubbles: true }));
    updateConstraintSummary();
  }

  function fillExample() {
    $('#hashes').value = '8743b52063cd84097a65d1633f5c74f5';
    $('#hash-mode').value = 'MD5';
    $('#hash-mode').dispatchEvent(new Event('change', { bubbles: true }));
    state.attack = 'mask';
    state.maskSource = 'builder';
    $('input[name="mask-source"][value="builder"]').checked = true;
    state.blocks = [{ type: 'literal', text: 'hashcat' }];
    state.customSets = ['', '', '', ''];
    $('#global-salt').value = '';
    $('#mask-builder').hidden = false;
    $('#mask-raw-wrap').hidden = true;
    clearConstraints();
    for (let i = 0; i < 4; i++) $('#custom-' + (i + 1)).value = '';
    renderBlocks();
    updateMaskPreview();
    setAttack('mask');
    updateHashSummary();
    $('#status').className = 'status success';
    $('#status').textContent = '已填入示例：MD5("hashcat")。点击“开始破解”即可看到命中结果。';
  }

  function fillRegexExample() {
    $('#hashes').value = 'b2157e7b2ae716a747597717f1efb7a0';
    $('#hash-mode').value = 'MD5';
    $('#hash-mode').dispatchEvent(new Event('change', { bubbles: true }));
    $('#regex-pattern').value = '[a-z]{3}\\d{2}';
    $('#regex-max-length').value = '8';
    $('#global-salt').value = '';
    clearConstraints();
    setAttack('regex');
    updateHashSummary();
    updateRegexPreview();
    $('#status').className = 'status success';
    $('#status').textContent = '已填入正则示例：MD5("abc12")，模式 [a-z]{3}\\d{2}。点击“开始破解”。';
  }

  function pickFiles(selector) {
    const element = $(selector);
    if (element) element.click();
  }

  function bindEvents() {
    $$('[data-pick]').forEach((button) => button.addEventListener('click', () => pickFiles('#' + button.dataset.pick)));
    $('#dict-folder').addEventListener('change', () => {
      showDictionaryFiles();
      $('#status').className = 'status success';
      $('#status').textContent = dictionaryFiles().length
        ? '已读取 ' + dictionaryFiles().length + ' 个 TXT 字典文件（README 已跳过）。'
        : '所选目录中没有可读取的 TXT 字典。';
    });
    $('#dict-files').addEventListener('change', () => {
      showDictionaryFiles();
      $('#status').className = 'status success';
      $('#status').textContent = dictionaryFiles().length
        ? '已读取 ' + dictionaryFiles().length + ' 个 TXT 字典文件。'
        : '没有找到可读取的 TXT 字典文件。';
    });

    $('#hashes').addEventListener('input', () => {
      clearTimeout(hashTimer);
      hashTimer = setTimeout(updateHashSummary, 180);
    });
    $('#hash-mode').addEventListener('change', () => {
      updateSaltUi();
      updateHashSummary();
    });
    $('#global-salt').addEventListener('input', () => {
      updateHashSummary();
      updateCommand();
    });

    $$('input[name="attack"]').forEach((input) => input.addEventListener('change', () => setAttack(input.value)));
    $$('input[name="mask-source"]').forEach((input) => input.addEventListener('change', () => {
      state.maskSource = input.value;
      $('#mask-builder').hidden = state.maskSource !== 'builder';
      $('#mask-raw-wrap').hidden = state.maskSource !== 'raw';
      updateMaskPreview();
    }));

    $('#add-block').addEventListener('click', () => {
      state.blocks.push({ type: 'digits', count: 2 });
      renderBlocks();
      updateMaskPreview();
    });
    $('#clear-blocks').addEventListener('click', () => {
      state.blocks = [];
      renderBlocks();
      updateMaskPreview();
    });
    $('#block-list').addEventListener('click', (event) => {
      const button = event.target.closest('button[data-action]');
      if (!button) return;
      const row = button.closest('.hc-block');
      const index = Number(row.dataset.index);
      const action = button.dataset.action;
      if (action === 'remove') state.blocks.splice(index, 1);
      else if (action === 'up' && index > 0) [state.blocks[index - 1], state.blocks[index]] = [state.blocks[index], state.blocks[index - 1]];
      else if (action === 'down' && index < state.blocks.length - 1) [state.blocks[index + 1], state.blocks[index]] = [state.blocks[index], state.blocks[index + 1]];
      else return;
      renderBlocks();
      updateMaskPreview();
    });

    $('#raw-mask').addEventListener('input', () => {
      state.rawMask = $('#raw-mask').value;
      updateMaskPreview();
    });
    for (let i = 1; i <= 4; i++) {
      $('#custom-' + i).addEventListener('input', (event) => {
        state.customSets[i - 1] = event.target.value;
        renderBlocks();
        updateMaskPreview();
      });
    }
    $$('[data-mask-preset]').forEach((button) => button.addEventListener('click', () => {
      const preset = MASK_PRESETS[Number(button.dataset.maskPreset)];
      if (!preset) return;
      state.maskSource = 'builder';
      $('input[name="mask-source"][value="builder"]').checked = true;
      $('#mask-builder').hidden = false;
      $('#mask-raw-wrap').hidden = true;
      state.blocks = preset.blocks.map((block) => Object.assign({}, block));
      state.customSets = (preset.custom || ['', '', '', '']).slice();
      for (let i = 0; i < 4; i++) $('#custom-' + (i + 1)).value = state.customSets[i];
      renderBlocks();
      updateMaskPreview();
    }));

    ['#rule-base', '#rule-trim', '#rule-reverse', '#rule-duplicate', '#rule-leet', '#rule-prefix', '#rule-suffix', '#rule-append-chars', '#rule-prepend-chars', '#rule-years', '#hybrid-direction']
      .forEach((selector) => {
        const element = $(selector);
        element.addEventListener(selector === '#rule-prefix' || selector === '#rule-suffix' || selector === '#rule-append-chars' || selector === '#rule-prepend-chars' ? 'input' : 'change', () => {
          updateRuleEstimate();
          updateRunSummary();
          updateCommand();
        });
      });
    $$('[data-fill-chars]').forEach((button) => button.addEventListener('click', () => {
      const target = $('#' + button.dataset.fillChars);
      target.value = button.dataset.chars;
      target.dispatchEvent(new Event('input', { bubbles: true }));
    }));

    $('#regex-pattern').addEventListener('input', () => {
      clearTimeout(regexTimer);
      regexTimer = setTimeout(updateRegexPreview, 220);
    });
    $('#regex-max-length').addEventListener('input', () => {
      clearTimeout(regexTimer);
      regexTimer = setTimeout(updateRegexPreview, 220);
    });
    $$('[data-regex-token]').forEach((button) => button.addEventListener('click', () => {
      const token = button.dataset.regexToken;
      const cursor = button.dataset.regexCursor === undefined ? undefined : Number(button.dataset.regexCursor);
      insertAtCursor($('#regex-pattern'), token, cursor);
    }));
    $$('[data-regex-preset]').forEach((button) => button.addEventListener('click', () => {
      $('#regex-pattern').value = button.dataset.regexPreset;
      updateRegexPreview();
    }));
    $('#regex-example').addEventListener('click', fillRegexExample);

    ['#constraint-min', '#constraint-max', '#constraint-lower', '#constraint-upper', '#constraint-digit', '#constraint-symbol',
      '#constraint-contains', '#constraint-contains-mode', '#constraint-ignore-case', '#constraint-require-any',
      '#constraint-require-all', '#constraint-exclude'].forEach((selector) => {
      const element = $(selector);
      element.addEventListener(element.tagName === 'SELECT' ? 'change' : 'input', () => {
        updateConstraintSummary();
        updateRunSummary();
        updateRegexPreviewIfNeeded();
        updateCommand();
      });
    });

    $('#start').addEventListener('click', startCrack);
    $('#stop').addEventListener('click', () => {
      if (!run) return;
      run.stop = true;
      if (run.pool) run.pool.close();
      $('#stop').disabled = true;
      $('#status').className = 'status warning';
      $('#status').textContent = '正在停止…';
    });
    $('#clear').addEventListener('click', () => {
      if (run) {
        $('#status').className = 'status warning';
        $('#status').textContent = '任务运行中，请先停止再清空结果。';
        return;
      }
      lastRun = null;
      renderResults(null);
      $('#status').className = 'status';
      $('#status').textContent = '已清空结果。';
      $('#progress').style.width = '0%';
      $('#progress-wrap').classList.remove('is-indeterminate');
      ['#stat-tested', '#stat-speed', '#stat-elapsed', '#stat-eta', '#stat-matched'].forEach((selector) => { $(selector).textContent = '—'; });
    });
    $('#copy-results').addEventListener('click', async () => {
      const text = collectResultText(lastRun);
      if (!text) { $('#status').className = 'status warning'; $('#status').textContent = '尚无结果可复制。'; return; }
      const ok = await copyText(text);
      $('#status').className = 'status ' + (ok ? 'success' : 'warning');
      $('#status').textContent = ok ? '结果已复制。' : '复制失败，请手动选择结果文本。';
    });
    $('#download-results').addEventListener('click', () => {
      const text = collectResultText(lastRun);
      if (!text) { $('#status').className = 'status warning'; $('#status').textContent = '尚无结果可导出。'; return; }
      const blob = new Blob([text + '\n'], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'hashcat-results-' + new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19) + '.txt';
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      $('#status').className = 'status success';
      $('#status').textContent = '结果已导出为 TXT 文件。';
    });
    $('#fill-example').addEventListener('click', fillExample);
    $('#download-sample').addEventListener('click', () => {
      const words = ['123456', 'password', 'Password1', 'hashcat', 'admin', 'letmein', 'qwerty', '2024', 'iloveyou', 'welcome', 'abc123', 'admin123'];
      const blob = new Blob([words.join('\n') + '\n'], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'sample-wordlist.txt';
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      $('#status').className = 'status success';
      $('#status').textContent = '示例字典已下载。请用“选择 TXT 文件”选中它再开始。';
    });
    $('#copy-command').addEventListener('click', async () => {
      const command = $('#hashcat-command');
      const ok = await copyText(command.textContent);
      if (!ok) {
        const range = document.createRange();
        range.selectNodeContents(command);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
      }
      $('#copy-command').textContent = ok ? '已复制' : '已选中，请手动复制';
      setTimeout(() => { $('#copy-command').textContent = '复制命令'; }, 1800);
    });
    $$('.hc-copy').forEach((button) => button.addEventListener('click', async () => {
      const block = button.closest('.hc-code-block');
      const code = block && block.querySelector('code');
      if (!code) return;
      const ok = await copyText(code.textContent);
      if (ok) {
        button.textContent = '已复制';
      } else {
        const range = document.createRange();
        range.selectNodeContents(code);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        button.textContent = '请手动复制';
      }
      setTimeout(() => { button.textContent = '复制'; }, 1800);
    }));
    $$('[data-doc-expand]').forEach((button) => button.addEventListener('click', () => $$('.hc-doc').forEach((doc) => { doc.open = true; })));
    $$('[data-doc-collapse]').forEach((button) => button.addEventListener('click', () => $$('.hc-doc').forEach((doc) => { doc.open = false; })));

  }

  function updateRegexPreviewIfNeeded() {
    if (state.attack === 'regex') updateRegexPreview();
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      try {
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        const ok = document.execCommand('copy');
        area.remove();
        return ok;
      } catch (_) {
        return false;
      }
    }
  }

  const MASK_PRESETS = [
    { label: '6 位数字', blocks: [{ type: 'digits', count: 6 }] },
    { label: '8 位小写', blocks: [{ type: 'lower', count: 8 }] },
    { label: '4 小写 + 2 数字', blocks: [{ type: 'lower', count: 4 }, { type: 'digits', count: 2 }] },
    { label: '1 大写 + 6 小写 + 2 数字', blocks: [{ type: 'upper', count: 1 }, { type: 'lower', count: 6 }, { type: 'digits', count: 2 }] },
    { label: '手机号 1 + 10 数字', blocks: [{ type: 'literal', text: '1' }, { type: 'digits', count: 10 }] },
    { label: '8 位字母数字', blocks: [{ type: 'custom1', count: 8 }], custom: ['?l?d', '', '', ''] }
  ];

  function init() {
    bindEvents();
    updateSaltUi();
    renderBlocks();
    $('#raw-mask').value = state.rawMask;
    $('#regex-pattern').value = state.regex.pattern;
    $('#regex-max-length').value = String(state.regex.maxLength);
    showDictionaryFiles();
    setAttack('mask');
    updateCustomSummary();
    updateMaskPreview();
    updateRegexPreview();
    updateConstraintSummary();
    updateHashSummary();
    updateRuleEstimate();
    renderResults(null);
    setRunning(false);
  }

  init();
  window.addEventListener('beforeunload', () => {
    if (workerUrl) URL.revokeObjectURL(workerUrl);
  });
})();
