(() => {
  const commands = window.LINUX_COMMANDS || [];
  const query = document.querySelector('#query');
  const categories = document.querySelector('#categories');
  const results = document.querySelector('#results');
  const summary = document.querySelector('#result-summary');
  const changesOnly = document.querySelector('#show-changes');
  const clear = document.querySelector('#clear-query');
  const pageSize = 36;
  let activeGroup = '全部';
  let activeSubcategory = '全部';
  let visibleCount = pageSize;

  document.querySelector('#total-count').textContent = `${commands.length} 条精选指令`;
  commands.forEach((item) => {
    const facet = getFacet(item);
    item.collection = facet.collection;
    item.subcollection = facet.subcollection;
  });
  const collectionNames = [...new Set(commands.map((item) => item.collection))];
  const categoryRows = document.createElement('div');
  categoryRows.className = 'category-rows';
  categories.append(categoryRows);

  function getFacet(item) {
    const name = item.name.toLowerCase();
    if (item.category === '关键目录与配置') {
      const isConfig = /^\/etc\//.test(name) || /(?:compose\.ya?ml|docker-compose\.yml|\.bashrc|\.profile)/.test(name);
      return { collection: '系统目录与配置', subcollection: isConfig ? '配置文件' : '系统目录' };
    }
    if (item.category === '容器与 Docker') {
      return { collection: '容器与平台', subcollection: name.startsWith('docker compose') ? 'Docker Compose' : 'Docker' };
    }
    if (item.category === '网站控制面板') {
      const subcollection = name.startsWith('bt') ? '宝塔面板' : name.startsWith('1pctl') || name.includes('1panel') ? '1Panel' : 'CloudPanel';
      return { collection: '容器与平台', subcollection };
    }
    if (item.category === '云平台与基础设施') {
      return { collection: '容器与平台', subcollection: name.includes('openstack') || name.startsWith('onestack') ? 'OpenStack' : '其他云平台' };
    }
    if (item.category === 'Web 服务与中间件') {
      const subcollection = /apache|httpd/.test(name) || /apache/i.test(item.description) ? 'Apache' : /nginx/i.test(name) || /nginx/i.test(item.description) ? 'Nginx' : '其他 Web 服务';
      return { collection: 'Web 服务与中间件', subcollection };
    }
    return { collection: 'Linux 基础', subcollection: item.category };
  }

  function countFor(collection, subcollection = null) {
    return commands.filter((item) => item.collection === collection && (subcollection === null || item.subcollection === subcollection)).length;
  }

  function renderCategories() {
    const collectionButtons = ['全部', ...collectionNames].map((name) => {
      const count = name === '全部' ? commands.length : countFor(name);
      const active = name === activeGroup;
      return `<button class="category-chip${active ? ' active' : ''}" type="button" data-collection="${escapeHTML(name)}" aria-pressed="${active}">${escapeHTML(name)}<span>${count}</span></button>`;
    }).join('');
    let subcategoryButtons = '';
    if (activeGroup !== '全部') {
      const names = [...new Set(commands.filter((item) => item.collection === activeGroup).map((item) => item.subcollection))];
      if (names.length > 1) {
        const allActive = activeSubcategory === '全部';
        subcategoryButtons = `<div class="subcategory-row" aria-label="${escapeHTML(activeGroup)}子合集"><button class="subcategory-chip${allActive ? ' active' : ''}" type="button" data-subcollection="全部" aria-pressed="${allActive}">全部子合集<span>${countFor(activeGroup)}</span></button>${names.map((name) => {
          const active = name === activeSubcategory;
          return `<button class="subcategory-chip${active ? ' active' : ''}" type="button" data-subcollection="${escapeHTML(name)}" aria-pressed="${active}">${escapeHTML(name)}<span>${countFor(activeGroup, name)}</span></button>`;
        }).join('')}</div>`;
      }
    }
    categoryRows.innerHTML = `<div class="collection-row" aria-label="指令合集">${collectionButtons}</div>${subcategoryButtons}`;
  }
  renderCategories();

  function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
  }

  function normalize(value) {
    return String(value).toLowerCase().replace(/[\s\-_/]+/g, ' ').trim();
  }

  function searchableText(item) {
    return normalize([item.name, item.category, item.syntax, item.description, item.examples.join(' '), item.keywords, item.purpose, item.howToEdit, item.notes].join(' '));
  }

  function editDistanceAtMostOne(left, right) {
    if (Math.abs(left.length - right.length) > 1) return false;
    let i = 0, j = 0, differences = 0;
    while (i < left.length && j < right.length) {
      if (left[i] === right[j]) { i++; j++; continue; }
      if (++differences > 1) return false;
      if (left.length > right.length) i++;
      else if (right.length > left.length) j++;
      else { i++; j++; }
    }
    return differences + (i < left.length || j < right.length ? 1 : 0) <= 1;
  }

  function termMatches(term, text) {
    if (text.includes(term)) return true;
    if (/^[\u3400-\u9fff]+$/.test(term)) {
      if (term.length === 1) return false;
      const grams = [];
      for (let i = 0; i < term.length - 1; i++) grams.push(term.slice(i, i + 2));
      const hits = grams.filter((gram) => text.includes(gram)).length;
      return hits >= Math.max(1, Math.ceil(grams.length * 0.45));
    }
    if (term.length < 4) return false;
    return text.split(/[^a-z0-9.+]+/).some((word) => word.length >= 3 && editDistanceAtMostOne(term, word));
  }

  function getMatches() {
    const terms = normalize(query.value).split(' ').filter(Boolean);
    return commands.filter((item) => {
      if (activeGroup !== '全部' && item.collection !== activeGroup) return false;
      if (activeSubcategory !== '全部' && item.subcollection !== activeSubcategory) return false;
      if (changesOnly.checked && !item.changes) return false;
      const text = searchableText(item);
      return terms.every((term) => termMatches(term, text));
    }).sort((a, b) => {
      const raw = normalize(query.value);
      const aExact = normalize(a.name) === raw ? 0 : 1;
      const bExact = normalize(b.name) === raw ? 0 : 1;
      const aContains = searchableText(a).includes(raw) ? 0 : 1;
      const bContains = searchableText(b).includes(raw) ? 0 : 1;
      const aPrefix = normalize(a.name).startsWith(raw) ? 0 : 1;
      const bPrefix = normalize(b.name).startsWith(raw) ? 0 : 1;
      return aExact - bExact || aPrefix - bPrefix || aContains - bContains || commands.indexOf(a) - commands.indexOf(b);
    });
  }

  function commandCard(item) {
    const examples = item.examples.map((example, index) => `<div class="example-line"><code>${escapeHTML(example)}</code><button class="copy-command" type="button" data-copy="${escapeHTML(example)}" aria-label="复制命令示例">复制</button></div>`).join('');
    const source = `<a class="command-source" href="${escapeHTML(item.source)}" target="_blank" rel="noopener noreferrer">${escapeHTML(item.sourceLabel || '教程 ↗')}</a>`;
    const impact = item.kind === 'path' ? '<span class="impact-badge path-badge">目录 / 配置说明</span>' : (item.changes ? '<span class="impact-badge changes">会改变系统或文件</span>' : '<span class="impact-badge read-only">查询 / 诊断</span>');
    const detail = item.kind === 'path' ? `<p class="path-purpose"><b>作用：</b>${escapeHTML(item.purpose)}</p><p class="path-edit"><b>查看 / 修改：</b>${escapeHTML(item.howToEdit)}</p>` : '';
    const note = item.notes ? `<p class="command-note">${escapeHTML(item.notes)}</p>` : '';
    return `<article class="command-card${item.kind === 'path' ? ' path-card' : ''}"><div class="command-card-top"><span class="category-label">${escapeHTML(item.category)}</span>${impact}</div><h2>${escapeHTML(item.name)}</h2><p class="command-syntax"><code>${escapeHTML(item.syntax)}</code></p><p class="command-description">${escapeHTML(item.description)}</p>${detail}${examples ? `<div class="examples">${examples}</div>` : ''}${note}<div class="command-card-footer">${source}</div></article>`;
  }

  function render() {
    const matches = getMatches();
    const shown = matches.slice(0, visibleCount);
    summary.textContent = matches.length ? `找到 ${matches.length} 条命令，当前显示 ${shown.length} 条` : '没有找到匹配的命令';
    results.innerHTML = shown.length
      ? `<div class="command-grid">${shown.map(commandCard).join('')}</div>${matches.length > shown.length ? `<div class="load-more-wrap"><button class="btn" id="load-more" type="button">再显示剩下 ${matches.length - shown.length} 条</button></div>` : ''}`
      : '<div class="panel empty-state"><strong>没有匹配结果</strong><p>试试更短的关键词，例如“端口”“日志”“压缩”或命令名。</p></div>';
    const loadMore = document.querySelector('#load-more');
    if (loadMore) loadMore.addEventListener('click', () => { visibleCount = matches.length; render(); });
    results.querySelectorAll('[data-copy]').forEach((button) => button.addEventListener('click', async () => {
      const original = button.textContent;
      try {
        await navigator.clipboard.writeText(button.dataset.copy);
        button.textContent = '已复制';
      } catch {
        const helper = document.createElement('textarea');
        helper.value = button.dataset.copy;
        helper.style.position = 'fixed'; helper.style.opacity = '0';
        document.body.append(helper); helper.select(); document.execCommand('copy'); helper.remove();
        button.textContent = '已复制';
      }
      setTimeout(() => { button.textContent = original; }, 1300);
    }));
  }

  categories.addEventListener('click', (event) => {
    const collectionButton = event.target.closest('[data-collection]');
    if (collectionButton) {
      activeGroup = collectionButton.dataset.collection;
      activeSubcategory = '全部';
      visibleCount = pageSize;
      renderCategories();
      render();
      return;
    }
    const button = event.target.closest('[data-subcollection]');
    if (!button) return;
    activeSubcategory = button.dataset.subcollection;
    visibleCount = pageSize;
    renderCategories();
    render();
  });
  query.addEventListener('input', () => { visibleCount = pageSize; render(); });
  changesOnly.addEventListener('change', () => { visibleCount = pageSize; render(); });
  clear.addEventListener('click', () => { query.value = ''; query.focus(); visibleCount = pageSize; render(); });
  render();
})();
