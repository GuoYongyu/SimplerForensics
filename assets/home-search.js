(() => {
  const input = document.querySelector('#tool-search-input');
  const status = document.querySelector('#tool-search-status');
  const results = document.querySelector('#tool-search-results');
  if (!input || !status || !results) return;

  const cards = [...document.querySelectorAll('.tool-card[data-search]')];
  const categories = [...document.querySelectorAll('.tool-category')];
  const extraSources = {
    'linux/index.html': [
      { path: 'linux/data.js' },
      { path: 'linux/supplement.js' },
      { path: 'linux/paths.js' }
    ],
    'market-search/index.html': [
      { path: 'market-search/data/questions.js' },
      { path: 'market-search/data/laws.js' },
      { path: 'market-search/data/laws-full.js' }
    ]
  };
  let indexPromise = null;
  let searchRun = 0;
  let debounceTimer = 0;

  const normalize = value => String(value || '').toLocaleLowerCase().normalize('NFKC').replace(/\s+/g, ' ').trim();
  const readResponse = async path => {
    const response = await fetch(new URL(path, location.href));
    if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
    return response.text();
  };

  const decodeSourceText = source => source.replace(/\\[rnt]/g, ' ').replace(/\\"/g, '"').replace(/\\\\/g, '\\');

  async function loadPage(card) {
    const path = card.getAttribute('href');
    const fallback = `${card.dataset.search || ''} ${card.textContent || ''}`;
    try {
      const source = await readResponse(path);
      const page = new DOMParser().parseFromString(source, 'text/html');
      const main = page.querySelector('main') || page.body;
      main.querySelectorAll('script,style,nav,header,footer,[hidden]').forEach(element => element.remove());
      const blocks = [...main.querySelectorAll('h1,h2,h3,h4,p,li,code,pre,td,th,label')];
      const content = blocks.map(element => element.textContent || '').join(' ').replace(/\s+/g, ' ').trim();
      const entry = {
        card,
        href: path,
        title: main.querySelector('h1')?.textContent.trim() || card.querySelector('h2')?.textContent.trim() || '工具页面',
        summary: card.querySelector('p')?.textContent.trim() || '',
        content
      };
      for (const sourceInfo of extraSources[path] || []) {
        try {
          const data = await readResponse(sourceInfo.path);
          entry.content += ` ${decodeSourceText(data)}`;
        } catch {}
      }
      entry.searchable = normalize(`${entry.title} ${card.dataset.search || ''} ${entry.summary} ${entry.content}`);
      entry.titleSearch = normalize(entry.title);
      entry.keywordSearch = normalize(card.dataset.search || '');
      return entry;
    } catch (error) {
      const title = card.querySelector('h2')?.textContent.trim() || '工具页面';
      return {
        card,
        href: path,
        title,
        summary: card.querySelector('p')?.textContent.trim() || '',
        content: fallback,
        searchable: normalize(fallback),
        titleSearch: normalize(title),
        keywordSearch: normalize(card.dataset.search || ''),
        unavailable: error
      };
    }
  }

  function buildIndex(activeRun) {
    if (!indexPromise) {
      indexPromise = (async () => {
        const entries = [];
        let unavailable = 0;
        for (let index = 0; index < cards.length; index++) {
          const entry = await loadPage(cards[index]);
          entries.push(entry);
          if (entry.unavailable) unavailable++;
          if (activeRun === searchRun) status.textContent = `正在建立本地内容索引… ${index + 1}/${cards.length}`;
          await new Promise(resolve => setTimeout(resolve, 0));
        }
        return { entries, unavailable };
      })();
    }
    return indexPromise;
  }

  function updateCards(query) {
    let visible = 0;
    for (const card of cards) {
      const match = !query || normalize(`${card.dataset.search} ${card.textContent}`).includes(query);
      card.hidden = !match;
      if (match) visible++;
    }
    for (const category of categories) category.hidden = !category.querySelector('.tool-card:not([hidden])');
    return visible;
  }

  function excerpt(content, terms) {
    const lower = content.toLocaleLowerCase();
    const positions = terms.map(term => lower.indexOf(term)).filter(position => position >= 0);
    const start = Math.max(0, (positions.length ? Math.min(...positions) : 0) - 55);
    const end = Math.min(content.length, start + 190);
    return `${start ? '…' : ''}${content.slice(start, end).trim()}${end < content.length ? '…' : ''}`;
  }

  function renderResults(matches) {
    results.replaceChildren();
    for (const match of matches.slice(0, 8)) {
      const item = document.createElement('article');
      item.className = 'tool-search-result';
      const heading = document.createElement('div');
      heading.className = 'tool-search-result-heading';
      const label = document.createElement('span');
      label.className = 'chip';
      label.textContent = match.source;
      const link = document.createElement('a');
      link.href = match.entry.href;
      link.textContent = `${match.entry.title} · 进入查看`;
      heading.append(label, link);
      const snippet = document.createElement('p');
      snippet.textContent = match.snippet;
      item.append(heading, snippet);
      results.append(item);
    }
    results.hidden = matches.length === 0;
  }

  async function search(query, run, cardMatches) {
    if (!query) {
      results.hidden = true;
      results.replaceChildren();
      status.textContent = '按用途浏览，或输入关键词筛选。';
      return;
    }
    if (query.length < 2) {
      results.hidden = true;
      results.replaceChildren();
      status.textContent = `工具名称匹配 ${cardMatches} 项；输入至少 2 个字符以检索页面详细内容。`;
      return;
    }

    results.hidden = true;
    status.textContent = '正在检索本地功能页和离线资料…';
    try {
      const { entries, unavailable } = await buildIndex(run);
      if (run !== searchRun) return;
      const terms = query.split(' ').filter(Boolean);
      const matches = [];
      for (const entry of entries) {
        if (!terms.every(term => entry.searchable.includes(term))) continue;
        let score = 0;
        if (entry.titleSearch.includes(query)) score += 100;
        if (entry.keywordSearch.includes(query)) score += 60;
        if (normalize(entry.summary).includes(query)) score += 35;
        if (entry.searchable.includes(query)) score += 20;
        score += terms.reduce((total, term) => total + (entry.titleSearch.includes(term) ? 8 : 0), 0);
        const contentSearch = normalize(entry.content);
        matches.push({ entry, score, source: terms.every(term => contentSearch.includes(term)) ? '页面内容命中' : '名称 / 用途命中', snippet: excerpt(entry.content, terms) });
      }
      matches.sort((left, right) => right.score - left.score || left.entry.title.localeCompare(right.entry.title, 'zh-CN'));
      renderResults(matches);
      if (matches.length) {
        status.textContent = `工具入口匹配 ${cardMatches} 项；在 ${matches.length} 个功能页内容中找到线索，选择下方推荐进入查看。${unavailable ? ` 有 ${unavailable} 个页面无法读取详细内容。` : ''}`;
      } else {
        status.textContent = `工具入口匹配 ${cardMatches} 项；功能页内容中未找到“${input.value.trim()}”。可尝试更短关键词或工具名称。${unavailable ? ' 如以 file:// 打开，请使用 launch.bat 启动本机服务以启用跨页面检索。' : ''}`;
      }
    } catch {
      if (run === searchRun) status.textContent = `工具入口匹配 ${cardMatches} 项；页面内容索引暂不可用。请通过 launch.bat 启动本机服务后重试。`;
    }
  }

  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    const query = normalize(input.value);
    const cardMatches = updateCards(query);
    const run = ++searchRun;
    debounceTimer = setTimeout(() => search(query, run, cardMatches), 180);
  });
})();
