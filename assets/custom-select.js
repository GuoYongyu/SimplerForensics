(()=>{
  const searchable = select => select.options.length > 10;
  document.querySelectorAll('select').forEach(select => {
    if (select.dataset.customized) return;
    select.dataset.customized = 'true';
    const wrap = document.createElement('div');
    wrap.className = 'custom-select';
    if (select.style.maxWidth) wrap.style.maxWidth = select.style.maxWidth;
    const enclosingLabel = select.closest('label');
    if (enclosingLabel && enclosingLabel.contains(select)) {
      const holder = document.createElement('div');
      holder.className = enclosingLabel.className;
      holder.style.cssText = enclosingLabel.style.cssText;
      const caption = enclosingLabel.querySelector('.field-label');
      if (caption) {
        const accessibleLabel = document.createElement('span');
        accessibleLabel.className = caption.className;
        accessibleLabel.id = `${select.id}-label`;
        accessibleLabel.textContent = caption.textContent;
        holder.appendChild(accessibleLabel);
        wrap.setAttribute('aria-labelledby', accessibleLabel.id);
      }
      enclosingLabel.replaceWith(holder);
      holder.appendChild(wrap);
    } else {
      select.parentNode.insertBefore(wrap, select);
    }
    wrap.appendChild(select);
    select.classList.add('native-select-hidden');
    const trigger = document.createElement('button');
    trigger.type = 'button'; trigger.className = 'select-trigger'; trigger.setAttribute('aria-haspopup','listbox'); trigger.setAttribute('aria-expanded','false');
    const label = document.createElement('span'), arrow = document.createElement('span'); arrow.className='select-arrow'; arrow.setAttribute('aria-hidden','true');
    trigger.append(label,arrow); wrap.appendChild(trigger);
    const menu = document.createElement('div'); menu.className='select-menu'; menu.hidden=true;
    let search;
    if (searchable(select)) { search=document.createElement('input'); search.className='select-search'; search.type='search'; search.placeholder='搜索选项…'; search.setAttribute('aria-label','搜索选项'); menu.appendChild(search); }
    const options = document.createElement('div'); options.className='select-options'; options.setAttribute('role','listbox'); menu.appendChild(options); wrap.appendChild(menu);
    const close=()=>{menu.hidden=true;trigger.setAttribute('aria-expanded','false');wrap.classList.remove('is-open');};
    const render=()=>{label.textContent=select.selectedOptions[0]?.textContent||'';options.replaceChildren();Array.from(select.options).forEach((option,index)=>{const item=document.createElement('button');item.type='button';item.className='select-option';item.setAttribute('role','option');item.setAttribute('aria-selected',String(index===select.selectedIndex));item.textContent=option.textContent;item.hidden=!!(search&&search.value&&!option.textContent.toLowerCase().includes(search.value.trim().toLowerCase()));item.addEventListener('click',()=>{select.selectedIndex=index;select.dispatchEvent(new Event('change',{bubbles:true}));render();close();trigger.focus();});options.appendChild(item);});};
    render();
    trigger.addEventListener('click',()=>{const opening=menu.hidden;document.querySelectorAll('.custom-select.is-open').forEach(other=>{if(other!==wrap)other.querySelector('.select-trigger').click();});menu.hidden=!opening;trigger.setAttribute('aria-expanded',String(opening));wrap.classList.toggle('is-open',opening);if(opening){if(search){search.value='';render();search.focus();}else options.querySelector('.select-option[aria-selected="true"]')?.scrollIntoView({block:'nearest'});}});
    trigger.addEventListener('keydown',e=>{if(['ArrowDown','Enter',' '].includes(e.key)){e.preventDefault();if(menu.hidden)trigger.click();else options.querySelector('.select-option:not([hidden])')?.focus();}});
    menu.addEventListener('keydown',e=>{const visible=[...options.querySelectorAll('.select-option:not([hidden])')],i=visible.indexOf(document.activeElement);if(e.key==='Escape'){close();trigger.focus();}else if(e.key==='ArrowDown'){e.preventDefault();visible[Math.min(i+1,visible.length-1)]?.focus();}else if(e.key==='ArrowUp'){e.preventDefault();if(i<=0)trigger.focus();else visible[i-1].focus();}});
    search?.addEventListener('input',render);
    select.addEventListener('change',render);
    document.addEventListener('click',e=>{if(!wrap.contains(e.target))close();});
  });
})();
