(() => {
  const questions = window.MARKET_QUESTIONS || [];
  const laws = window.MARKET_LAWS || [];
  const fullLaws = window.MARKET_FULL_LAWS || [];
  const query = document.querySelector('#query');
  const filters = document.querySelector('#filters');
  const results = document.querySelector('#results');
  const summary = document.querySelector('#result-summary');
  const importPanel = document.querySelector('#import-panel');
  const importFiles = document.querySelector('#import-files');
  const importStatus = document.querySelector('#import-status');
  const officialDatabase = 'https://sjfg.samr.gov.cn/law/pageInfo/main.main';
  let activeGroup = '题库';
  let visibleCount = 40;
  const storageKey = 'simplerforensic-market-search-imports-v1';
  const categoryAliases = {
    '价格与竞争':'价格竞争', '价格收费监督检查':'价格竞争', '反垄断执法':'价格竞争', '反不正当竞争监督管理':'价格竞争',
    '消费与交易':'消费', '广告与网络交易':'广告网络', '网络市场交易监督管理':'网络交易', '广告监督管理':'广告',
    '食品安全监督管理':'食品', '食品安全':'食品', '特种设备安全监督管理':'特种设备', '特种设备':'特种设备',
    '产品质量':'产品质量', '质量发展与安全监督管理':'产品质量', '登记与信用':'登记信用', '市场主体登记注册':'登记信用',
    '市场主体信用监督管理':'登记信用', '综合执法':'执法', '市场监管综合执法':'执法', '计量监督管理':'计量标准',
    '标准化监督管理':'计量标准', '认证认可与检验检测监督管理':'计量标准', '规范直销和打击传销':'直销传销',
    '知识产权':'知识产权', '药品监督管理':'药品', '价格与竞争':'价格竞争', '题库':'题库', '导入资料':'导入'
  };
  function simpleCategory(value) {
    const name = String(value || '其他');
    return categoryAliases[name] || (name.length > 8 ? `${name.slice(0, 7)}…` : name);
  }

  function readImports() {
    try {
      let saved = localStorage.getItem(storageKey);
      if (saved === null) {
        saved = localStorage.getItem('littletools-market-search-imports-v1');
        if (saved !== null) localStorage.setItem(storageKey, saved);
      }
      const value = JSON.parse(saved || '[]');
      return Array.isArray(value) ? value.filter((item) => item && typeof item.content === 'string') : [];
    } catch { return []; }
  }
  let imported = readImports();
  const normalize = (value) => String(value || '').toLocaleLowerCase().normalize('NFKC').replace(/[\s\-_/，。；、：！？（）【】《》“”‘’]+/g, ' ').trim();
  const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const questionDocs = questions.map((item) => ({
    id: `q-${item.id}`, type: 'question', group: '题库', category: '题库', title: item.question,
    content: item.question, options: item.options, answer: item.answer, questionType: item.type,
    keywords: `${item.type} ${item.options} ${item.answer}`, source: `题库原始序号 ${item.id}`
  }));
  const summaries = new Map(laws.map((item) => [item.title, item]));
  const lawDocs = fullLaws.map((item) => {
    const summary = summaries.get(item.title) || {};
    return {
      ...item, id: `law-${item.id}`, type: 'law', group: '法律法规', category: simpleCategory(item.category || summary.category || '其他'),
      content: item.text || summary.content || '', keywords: summary.keywords || '',
      source: item.source || '国家市场监督管理总局法规数据库'
    };
  });
  function allDocs() { return [...lawDocs, ...questionDocs, ...imported]; }
  function groupFor(item) {
    if (item.group === '题库' || item.group === '法律法规') return item.group;
    return item.type === 'question' || item.questionType || item.category === '题库' || item.question ? '题库' : '法律法规';
  }
  document.querySelector('#total-count').textContent = `${questionDocs.length.toLocaleString()} 道题 · ${fullLaws.length} 条法规全文索引`;

  function renderFilters() {
    const counts = allDocs().reduce((map, item) => { const group = groupFor(item); map[group] = (map[group] || 0) + 1; return map; }, {});
    const groups = ['题库', '法律法规'];
    filters.innerHTML = groups.map((name) => `<button class="category-chip${name === activeGroup ? ' active' : ''}" type="button" data-group="${name}" aria-pressed="${name === activeGroup}">${name}<span>${(counts[name] || 0).toLocaleString()}</span></button>`).join('');
  }

  function editDistanceAtMostOne(a, b) {
    if (Math.abs(a.length - b.length) > 1) return false;
    let i = 0, j = 0, differences = 0;
    while (i < a.length && j < b.length) {
      if (a[i] === b[j]) { i++; j++; continue; }
      if (++differences > 1) return false;
      if (a.length > b.length) i++;
      else if (b.length > a.length) j++;
      else { i++; j++; }
    }
    return differences + (i < a.length || j < b.length ? 1 : 0) <= 1;
  }
  function termMatches(term, text) {
    if (text.includes(term)) return 1;
    if (/^[\u3400-\u9fff]+$/.test(term)) {
      if (term.length === 1) return 0;
      const grams = [];
      for (let i = 0; i < term.length - 1; i++) grams.push(term.slice(i, i + 2));
      const hits = grams.filter((gram) => text.includes(gram)).length;
      const ratio = hits / grams.length;
      return ratio >= 0.4 ? ratio : 0;
    }
    if (term.length < 4) return 0;
    return text.split(/[^a-z0-9.+]+/).some((word) => word.length >= 3 && editDistanceAtMostOne(term, word)) ? 0.55 : 0;
  }
  function highlightText(value) {
    const text = String(value ?? '');
    const terms = normalize(query.value).split(' ').filter(Boolean);
    if (!terms.length || !text) return escapeHTML(text);
    const lower = text.toLocaleLowerCase();
    const ranges = [];
    const addOccurrences = (needle) => {
      if (!needle) return 0;
      let found = 0, from = 0;
      while (from < lower.length) {
        const at = lower.indexOf(needle, from);
        if (at < 0) break;
        ranges.push([at, at + needle.length]); found++; from = at + needle.length;
      }
      return found;
    };
    for (const term of terms) {
      if (addOccurrences(term)) continue;
      if (/^[\u3400-\u9fff]+$/.test(term) && term.length > 1) {
        for (let i = 0; i < term.length - 1; i++) addOccurrences(term.slice(i, i + 2));
      } else if (term.length >= 4) {
        for (const match of text.matchAll(/[a-z0-9.+]+/gi)) {
          if (match[0].length >= 3 && editDistanceAtMostOne(term, match[0].toLocaleLowerCase())) ranges.push([match.index, match.index + match[0].length]);
        }
      }
    }
    if (!ranges.length) return escapeHTML(text);
    ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    const merged = [];
    for (const range of ranges) {
      const last = merged[merged.length - 1];
      if (last && range[0] <= last[1]) last[1] = Math.max(last[1], range[1]);
      else merged.push([...range]);
    }
    let output = '', cursor = 0;
    for (const [start, end] of merged) {
      output += escapeHTML(text.slice(cursor, start)) + `<mark class="search-highlight">${escapeHTML(text.slice(start, end))}</mark>`;
      cursor = end;
    }
    return output + escapeHTML(text.slice(cursor));
  }
  function excerptFor(item) {
    const text = String(item.content || '');
    if (item.type !== 'law' || text.length <= 300) return text;
    const terms = normalize(query.value).split(' ').filter(Boolean);
    let at = terms.map((term) => text.toLocaleLowerCase().indexOf(term)).filter((index) => index >= 0).sort((a, b) => a - b)[0];
    if (at === undefined) {
      for (const term of terms) {
        for (let i = 0; i < term.length - 1; i++) {
          const found = text.indexOf(term.slice(i, i + 2));
          if (found >= 0 && (at === undefined || found < at)) at = found;
        }
      }
    }
    if (at === undefined) at = 0;
    const start = Math.max(0, at - 100);
    const end = Math.min(text.length, start + 300);
    return `${start ? '…' : ''}${text.slice(start, end)}${end < text.length ? '…' : ''}`;
  }
  function search() {
    const terms = normalize(query.value).split(' ').filter(Boolean);
    return allDocs().filter((item) => {
      if (groupFor(item) !== activeGroup) return false;
      if (!terms.length) return true;
      const text = normalize([item.title, item.content, item.options, item.answer, item.keywords, item.questionType].join(' '));
      return terms.every((term) => termMatches(term, text));
    }).map((item) => {
      const text = normalize([item.title, item.content, item.options, item.answer, item.keywords].join(' '));
      const raw = normalize(query.value);
      const score = (raw && normalize(item.title).includes(raw) ? 100 : 0) + terms.reduce((total, term) => total + termMatches(term, text), 0);
      return { item, score };
    }).sort((a, b) => b.score - a.score || a.item.title.localeCompare(b.item.title, 'zh-CN')).map(({item}) => item);
  }
  function card(item) {
    const badge = item.type === 'question' ? `${item.questionType || '题目'} · ${item.category}` : item.type === 'law' ? `${item.validitySource ? '状态提示' : '效力'}：${item.validity || '未标注'} · ${item.category}` : `${item.category || '导入'}`;
    const options = item.options ? `<div class="question-options">${highlightText(item.options)}</div>` : '';
    const answer = item.answer ? `<div class="answer"><b>答案：</b>${highlightText(item.answer)}</div>` : '';
    const link = item.sourceUrl && /^https?:\/\//i.test(item.sourceUrl) ? item.sourceUrl : (item.url && /^https?:\/\//i.test(item.url) ? item.url : officialDatabase);
    const source = item.type === 'question' ? escapeHTML(item.source) : `<a href="${escapeHTML(link)}" target="_blank" rel="noopener noreferrer">来源</a>`;
    const body = excerptFor(item);
    const localPdf = item.pdf ? `<a class="local-law-link" href="${escapeHTML(item.pdf)}" target="_blank" rel="noopener">查看全文</a>` : '<span class="source-label">暂无本地原文</span>';
    const title = item.type === 'law' && item.pdf ? `<a href="${escapeHTML(item.pdf)}" target="_blank" rel="noopener">${highlightText(item.title || '未命名资料')}</a>` : highlightText(item.title || '未命名资料');
    const metadata = item.type === 'law' ? `<p class="law-details">${escapeHTML(item.validLevel || '')}${item.publishedTime ? ` · ${escapeHTML(String(item.publishedTime).slice(0, 10))}` : ''}${item.startTime ? ` · 施行 ${escapeHTML(String(item.startTime).slice(0, 10))}` : ''}${item.validitySource ? ` · ${escapeHTML(item.validitySource)}` : ''}</p>` : '';
    const bodyHtml = body && item.type !== 'question' ? `<p>${highlightText(body)}</p>` : '';
    return `<article class="market-card"><div class="market-meta"><span>${escapeHTML(badge)}</span><span class="source-label">${source}</span></div><h2>${title}</h2>${bodyHtml}${metadata}${options}${answer}${item.type === 'law' ? `<div class="law-links">${localPdf}</div>` : ''}</article>`;
  }
  function render() {
    const matches = search();
    const shown = matches.slice(0, visibleCount);
    summary.textContent = matches.length ? `找到 ${matches.length.toLocaleString()} 条，当前显示 ${shown.length}` : '没有找到匹配内容';
    results.innerHTML = shown.length ? `<div class="market-grid">${shown.map(card).join('')}</div>${matches.length > shown.length ? `<div class="load-more-wrap"><button class="btn" id="load-more" type="button">继续显示 ${Math.min(100, matches.length - shown.length)} 条</button></div>` : ''}` : '<div class="panel empty-state"><strong>没有匹配结果</strong><p>试试更短的关键词，或切换到另一个分类。</p></div>';
    document.querySelector('#load-more')?.addEventListener('click', () => { visibleCount += 100; render(); });
  }
  function parseCsv(text) {
    const rows = []; let row = [], cell = '', quoted = false;
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (quoted && char === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (char === '"') quoted = !quoted;
      else if (char === ',' && !quoted) { row.push(cell); cell = ''; }
      else if ((char === '\n' || char === '\r') && !quoted) { if (cell || row.length) { row.push(cell); rows.push(row); } row = []; cell = ''; if (char === '\r' && text[i + 1] === '\n') i++; }
      else cell += char;
    }
    if (cell || row.length) { row.push(cell); rows.push(row); }
    if (rows.length < 2) return [];
    const headers = rows.shift().map((v) => v.trim());
    return rows.filter((cells) => cells.some((v) => v.trim())).map((cells) => Object.fromEntries(headers.map((key, i) => [key, cells[i] || ''])));
  }
  function normalizeImported(value, filename) {
    const entries = Array.isArray(value) ? value : (Array.isArray(value?.items) ? value.items : [value]);
    return entries.filter((item) => item && typeof item === 'object').map((item, index) => {
      const question = item.question || item['题干'];
      const title = item.title || item['标题'] || question || `${filename} · ${index + 1}`;
      const content = item.content || item.text || item['内容'] || question || '';
      const options = item.options || item['选项'] || '';
      const answer = item.answer || item['正确答案'] || item['答案'] || '';
      const group = question || item.type === 'question' || item['题型'] ? '题库' : '法律法规';
      return { id: `import-${Date.now()}-${Math.random().toString(36).slice(2)}-${index}`, type: 'import', group, category: simpleCategory(item.category || item['分类'] || (group === '题库' ? '题库' : '导入')), title: String(title), content: String(content), options: String(options), answer: String(answer), keywords: String(item.keywords || item['关键词'] || ''), source: String(item.source || filename), url: String(item.url || '') };
    }).filter((item) => item.content || item.options || item.answer);
  }
  function setImportStatus(message, type = 'success') { importStatus.textContent = message; importStatus.className = `status ${type}`; importStatus.hidden = false; }
  filters.addEventListener('click', (event) => { const button = event.target.closest('[data-group]'); if (!button) return; activeGroup = button.dataset.group; visibleCount = 40; renderFilters(); render(); });
  query.addEventListener('input', () => { visibleCount = 40; render(); });
  document.querySelector('#clear-query').addEventListener('click', () => { query.value = ''; query.focus(); visibleCount = 40; render(); });
  document.querySelector('#import-toggle').addEventListener('click', () => { importPanel.hidden = !importPanel.hidden; });
  importFiles.addEventListener('change', async () => {
    let added = 0, failures = [];
    for (const file of importFiles.files || []) {
      try {
        const text = await file.text();
        let records;
        if (/\.json$/i.test(file.name)) records = normalizeImported(JSON.parse(text.replace(/^\uFEFF/, '')), file.name);
        else if (/\.csv$/i.test(file.name)) records = normalizeImported(parseCsv(text), file.name);
        else records = [{ id: `import-${Date.now()}-${Math.random().toString(36).slice(2)}`, type: 'import', category: '导入资料', title: file.name.replace(/\.(txt|md)$/i, ''), content: text, keywords: '', source: file.name }];
        imported.push(...records); added += records.length;
      } catch (error) { failures.push(`${file.name}：${error.message}`); }
    }
    try {
      localStorage.setItem(storageKey, JSON.stringify(imported));
      renderFilters(); render();
      setImportStatus(`已导入 ${added} 条。本机共保存 ${imported.length} 条。${failures.length ? `导入失败：${failures.join('；')}` : ''}`, failures.length ? 'warning' : 'success');
    } catch (error) { setImportStatus(`保存失败：浏览器存储空间不足。${error.message}`, 'error'); }
    importFiles.value = '';
  });
  document.querySelector('#export-imports').addEventListener('click', () => {
    if (!imported.length) { setImportStatus('当前没有已导入的资料。', 'warning'); return; }
    const blob = new Blob([JSON.stringify(imported, null, 2)], {type:'application/json'});
    const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = '市场监管检索-本地导入.json'; anchor.click(); URL.revokeObjectURL(url);
  });
  document.querySelector('#clear-imports').addEventListener('click', () => {
    if (!imported.length) return;
    imported = []; localStorage.removeItem(storageKey); renderFilters(); render(); setImportStatus('已清除当前浏览器保存的导入资料。', 'warning');
  });
  renderFilters(); render();
})();
