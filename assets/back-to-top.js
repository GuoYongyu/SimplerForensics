(() => {
  const button = document.createElement('button');
  button.className = 'back-to-top';
  button.type = 'button';
  button.setAttribute('aria-label', '回到页面顶部');
  button.title = '回到页面顶部';
  button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 19V5M5.5 11.5 12 5l6.5 6.5" /></svg>';
  document.body.append(button);

  const updateVisibility = () => {
    button.classList.toggle('is-visible', window.scrollY > 320);
  };
  window.addEventListener('scroll', updateVisibility, { passive: true });
  updateVisibility();

  button.addEventListener('click', () => {
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    window.scrollTo({ top: 0, behavior: reducedMotion ? 'instant' : 'smooth' });
  });
})();
