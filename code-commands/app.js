(() => {
  const entries = window.CODE_COMMANDS || [];
  const query = document.querySelector('#query');
  const categories = document.querySelector('#categories');
  const results = document.querySelector('#results');
  const summary = document.querySelector('#result-summary');
  const changesOnly = document.querySelector('#show-changes');
  const pageSize = 36;
  let activeCategory = '全部';
  let visibleCount = pageSize;
  const categoryNames = [...new Set(entries.map((item) => item.category))];
  document.querySelector('#total-count').textContent = entries.length + ' 条本地指令';

  function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
  }
  function normalize(value) {
    return String(value).toLocaleLowerCase().replace(/[\s\-_/]+/g, ' ').trim();
  }
  function renderCategories() {
    const all = ['全部', ...categoryNames];
    categories.innerHTML = '<div class="category-rows"><div class="collection-row" aria-label="命令分类">' + all.map((name) => {
      const count = name === '全部' ? entries.length : entries.filter((item) => item.category === name).length;
      const active = name === activeCategory;
      return '<button class="category-chip' + (active ? ' active' : '') + '" type="button" data-category="' + escapeHTML(name) + '" aria-pressed="' + active + '">' + escapeHTML(name) + '<span>' + count + '</span></button>';
    }).join('') + '</div></div>';
  }
  function searchable(item) {
    return normalize([item.category, item.name, item.syntax, item.description, item.examples.join(' '), item.keywords, item.source].join(' '));
  }
  function matches() {
    const terms = normalize(query.value).split(' ').filter(Boolean);
    return entries.map((item, index) => ({ item, index })).filter(({ item }) => {
      if (activeCategory !== '全部' && item.category !== activeCategory) return false;
      if (changesOnly.checked && !item.risk) return false;
      const text = searchable(item);
      return terms.every((term) => text.includes(term));
    }).sort((a, b) => {
      const raw = normalize(query.value);
      if (!raw) return a.index - b.index;
      const score = ({ item }) => normalize(item.name) === raw ? 0 : normalize(item.name).startsWith(raw) ? 1 : searchable(item).includes(raw) ? 2 : 3;
      return score(a) - score(b) || a.index - b.index;
    }).map(({ item }) => item);
  }
  function card(item) {
    const examples = item.examples.map((example) => '<div class="example-line"><code>' + escapeHTML(example) + '</code><button class="copy-command" type="button" data-copy="' + escapeHTML(example) + '" aria-label="复制命令示例">复制</button></div>').join('');
    const badge = item.risk ? '<span class="impact-badge changes">会改变环境</span>' : '<span class="impact-badge read-only">查询 / 构建 / 运行</span>';
    return '<article class="command-card"><div class="command-card-top"><span class="category-label">' + escapeHTML(item.category) + '</span>' + badge + '</div><h2>' + escapeHTML(item.name) + '</h2><p class="command-syntax"><code>' + escapeHTML(item.syntax) + '</code></p><p class="command-description">' + escapeHTML(item.description) + '</p><div class="examples">' + examples + '</div><div class="command-card-footer"><span class="local-source">参考：' + escapeHTML(item.source) + '</span></div></article>';
  }
  function render() {
    const found = matches();
    const shown = found.slice(0, visibleCount);
    summary.textContent = found.length ? '找到 ' + found.length + ' 条指令，当前显示 ' + shown.length + ' 条' : '没有找到匹配的指令';
    results.innerHTML = shown.length
      ? '<div class="command-grid">' + shown.map(card).join('') + '</div>' + (found.length > shown.length ? '<div class="load-more-wrap"><button class="btn" id="load-more" type="button">再显示 ' + (found.length - shown.length) + ' 条</button></div>' : '')
      : '<div class="panel empty-state"><strong>没有匹配结果</strong><p>试试语言名、命令名或短一些的用途词，例如“证书”“编译”“测试”“依赖”。</p></div>';
    const more = document.querySelector('#load-more');
    if (more) more.addEventListener('click', () => { visibleCount += pageSize; render(); });
    results.querySelectorAll('[data-copy]').forEach((button) => button.addEventListener('click', async () => {
      const original = button.textContent;
      try {
        await navigator.clipboard.writeText(button.dataset.copy);
      } catch {
        const helper = document.createElement('textarea');
        helper.value = button.dataset.copy; helper.style.position = 'fixed'; helper.style.opacity = '0';
        document.body.append(helper); helper.select(); document.execCommand('copy'); helper.remove();
      }
      button.textContent = '已复制';
      setTimeout(() => { button.textContent = original; }, 1300);
    }));
  }
  renderCategories();
  categories.addEventListener('click', (event) => {
    const button = event.target.closest('[data-category]');
    if (!button) return;
    activeCategory = button.dataset.category; visibleCount = pageSize; renderCategories(); render();
  });
  query.addEventListener('input', () => { visibleCount = pageSize; render(); });
  changesOnly.addEventListener('change', () => { visibleCount = pageSize; render(); });
  document.querySelector('#clear-query').addEventListener('click', () => { query.value = ''; query.focus(); visibleCount = pageSize; render(); });
  document.querySelectorAll('[data-query]').forEach((button) => button.addEventListener('click', () => { query.value = button.dataset.query; visibleCount = pageSize; render(); query.focus(); }));
  document.addEventListener('keydown', (event) => {
    if (event.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) { event.preventDefault(); query.focus(); }
    if (event.key === 'Escape' && document.activeElement === query) { query.value = ''; visibleCount = pageSize; render(); }
  });
  render();
})();