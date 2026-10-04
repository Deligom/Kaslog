// ============================================================
// ERİŞİLEBİLİRLİK KATMANI
//
// Uygulama arayüzü innerHTML şablonlarıyla çiziliyor ve tıklanan öğelerin çoğu
// <div onclick>. Bu öğeler klavyeyle odaklanamıyor, ekran okuyucuya "düğme"
// olarak görünmüyor. Her şablona tek tek rol eklemek yerine burada TEK noktadan
// (MutationObserver) şunlar sağlanır:
//
//   • onclick'li, yerel olmayan öğeler → role=button + tabindex=0 + Enter/Boşluk
//   • simge düğmeleri title'dan aria-label alır
//   • form etiketleri alanlarla ilişkilendirilir; etiketsiz alanlar placeholder'dan ad alır
//   • sınıfla tutulan durumlar (active/selected/on) aria-pressed / aria-checked / aria-current olur
//   • açılır pencereler: role=dialog, odak yönetimi, arka plan `inert`, Escape ile kapanma
//   • satır sırası değiştirme tutamacı klavyeyle (yukarı/aşağı ok) kullanılabilir
//
// Davranışa dokunmaz: işaretlemeye ve odağa ekleme yapar, mevcut işleyicileri değiştirmez.
// ============================================================

/** Canvas grafikleri ekran okuyucuya görünmez; veriyi kısa bir metin olarak ver. */
function chartLabel(canvas, text) {
  if (!canvas) return;
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', text);
}

(function () {
  const NATIVE = new Set(['BUTTON', 'A', 'INPUT', 'SELECT', 'TEXTAREA', 'SUMMARY', 'LABEL']);
  const INTERACTIVE = 'button,a[href],input,select,textarea,[role="button"],[role="switch"],[tabindex]:not([tabindex="-1"])';
  // Escape ile kapanmaması gerekenler: bir karar bekleyen pencereler (kapatmak
  // taslağı silebilir ya da bekleyen kaydı yarım bırakabilir).
  const NO_ESCAPE = new Set(['modal-alert', 'modal-readiness', 'modal-tarif-mi']);
  const PRESSED_CLASSES = ['.pill', '.level-card', '.goal-card', '.nut-day-btn', '.wo-chip-active', '#wo-warmup-chip'];
  let counter = 0;
  const uid = p => p + '-' + (++counter);

  // ── Düğme gibi davranan öğeler ──────────────────────────────
  function enhanceClickable(el) {
    if (NATIVE.has(el.tagName) || el.hasAttribute('role')) return;
    // İçinde başka etkileşimli öğe varsa (satır + silme düğmesi) kapsayıcıyı düğme
    // yapma: iç içe etkileşim ekran okuyucuyu bozar. İç düğmeler zaten odaklanır
    // ve tıklama kapsayıcıya kabarcıklanır.
    if (el.querySelector(INTERACTIVE)) return;
    el.setAttribute('role', el.classList.contains('toggle') ? 'switch' : 'button');
    if (!el.hasAttribute('tabindex')) el.tabIndex = 0;
  }

  function enhanceNames(el) {
    // Ayarlar'daki anahtarlar: ad, aynı satırdaki başlıktan gelir
    if (el.classList.contains('toggle') && !el.hasAttribute('aria-labelledby') && !el.hasAttribute('aria-label')) {
      const t = el.closest('.settings-row')?.querySelector('.settings-row-title');
      if (t) { if (!t.id) t.id = uid('ayar'); el.setAttribute('aria-labelledby', t.id); }
    }
    // Metni yalnızca simge/noktalama olan düğme: title'ı ad olarak kullan
    if (el.matches('button,[role="button"],[role="switch"]') && !el.hasAttribute('aria-label')) {
      const title = el.getAttribute('title');
      if (title && !/\p{L}/u.test((el.textContent || '').trim())) el.setAttribute('aria-label', title);
    }
  }

  function enhanceFields(root) {
    for (const g of root.querySelectorAll('.form-group')) {
      const label = g.querySelector('label'), field = g.querySelector('input,select,textarea');
      if (!label || !field || label.htmlFor) continue;
      if (!field.id) field.id = uid('alan');
      label.htmlFor = field.id;
    }
    for (const f of root.querySelectorAll('input:not([type="hidden"]),textarea,select')) {
      if (f.hasAttribute('aria-label') || f.hasAttribute('aria-labelledby')) continue;
      if (f.id && document.querySelector(`label[for="${CSS.escape(f.id)}"]`)) continue;
      if (f.closest('label')) continue;
      const prev = f.previousElementSibling;
      if (prev && prev.classList.contains('wo-input-label')) {    // antrenman ekranı: ağırlık / tekrar
        if (!prev.id) prev.id = uid('etiket');
        f.setAttribute('aria-labelledby', prev.id);
      } else if (f.placeholder || f.title) {
        f.setAttribute('aria-label', f.title || f.placeholder);
      }
    }
  }

  // ── Sınıfla tutulan durumları ARIA'ya yansıt ───────────────
  function syncState(el) {
    if (el.nodeType !== 1) return;
    if (el.getAttribute('role') === 'switch') {
      el.setAttribute('aria-checked', el.classList.contains('on') ? 'true' : 'false');
    }
    if (el.classList.contains('nav-item')) {
      if (el.classList.contains('active')) el.setAttribute('aria-current', 'page'); else el.removeAttribute('aria-current');
    }
    if (el.classList.contains('sticky-tab')) {
      if (el.classList.contains('active')) el.setAttribute('aria-current', 'true'); else el.removeAttribute('aria-current');
    }
    if (PRESSED_CLASSES.some(s => el.matches(s)) && el.matches('[role="button"],button')) {
      const on = el.classList.contains('active') || el.classList.contains('selected') || el.classList.contains('wo-chip-active');
      el.setAttribute('aria-pressed', on ? 'true' : 'false');
    }
  }

  const STATE_SEL = '[role="switch"],.nav-item,.sticky-tab,' + PRESSED_CLASSES.join(',');

  function enhanceTree(root) {
    if (root.nodeType !== 1 && root.nodeType !== 9 && root.nodeType !== 11) return;
    const els = [];
    if (root.nodeType === 1 && root.matches('[onclick]')) els.push(root);
    els.push(...root.querySelectorAll('[onclick]'));
    els.forEach(enhanceClickable);
    // Sıra tutamacı: klavyeyle yukarı/aşağı ok
    const handles = root.nodeType === 1 && root.matches('.dex-drag-handle') ? [root] : [];
    handles.push(...root.querySelectorAll('.dex-drag-handle'));
    for (const h of handles) {
      h.setAttribute('role', 'button'); h.tabIndex = 0;
      h.setAttribute('aria-label', 'Hareketin sırasını değiştir: yukarı veya aşağı ok tuşu');
    }
    const named = [];
    if (root.nodeType === 1 && root.matches('button,[role="button"],[role="switch"],.toggle')) named.push(root);
    named.push(...root.querySelectorAll('button,[role="button"],[role="switch"],.toggle'));
    named.forEach(enhanceNames);
    if (root.nodeType === 1 || root.nodeType === 9) enhanceFields(root);
    const stateEls = [];
    if (root.nodeType === 1 && root.matches(STATE_SEL)) stateEls.push(root);
    stateEls.push(...root.querySelectorAll(STATE_SEL));
    stateEls.forEach(syncState);
  }

  // ── Açılır pencereler ───────────────────────────────────────
  function layers() {
    // Antrenman ekranı ve pencereler DOM'da bu sırayla durur; sonuncu en üsttedir.
    return [...document.querySelectorAll('#workout-overlay.open, .modal-backdrop.open')];
  }

  function syncInert() {
    const open = layers();
    const top = open[open.length - 1] || null;
    const app = document.getElementById('app');
    if (!app) return;
    for (const child of app.children) {
      if (child.id === 'toast-el' || child.id === 'pr-banner') continue;     // canlı bölgeler
      const aktif = !top || child === top;
      if (aktif) child.removeAttribute('inert'); else child.setAttribute('inert', '');
    }
  }

  function setupDialogs() {
    for (const bd of document.querySelectorAll('.modal-backdrop')) {
      const box = bd.querySelector('.modal-sheet,.dialog-box,.modal');
      if (!box || box.hasAttribute('role')) continue;
      box.setAttribute('role', 'dialog');
      box.setAttribute('aria-modal', 'true');
      box.tabIndex = -1;
      if (box.hasAttribute('aria-label')) continue;       // HTML'de elle adlandırılmış
      const title = box.querySelector('.modal-title,[id$="-title"],[id$="-baslik"]') ||
                    [...box.children].find(c => (c.textContent || '').trim());
      if (title) { if (!title.id) title.id = uid('baslik'); box.setAttribute('aria-labelledby', title.id); }
    }
    const wo = document.getElementById('workout-overlay');
    if (wo) { wo.setAttribute('role', 'dialog'); wo.setAttribute('aria-modal', 'true'); wo.setAttribute('aria-label', 'Aktif antrenman'); wo.tabIndex = -1; }
  }

  function onLayerToggle(el) {
    const open = el.classList.contains('open');
    if (open === !!el._a11yOpen) return;
    el._a11yOpen = open;
    if (open) {
      const ae = document.activeElement;
      el._a11yOpener = (ae && ae !== document.body && !el.contains(ae)) ? ae : null;
      syncInert();
      // Odak, pencerenin kendisine (başlığı okunsun). İlk Tab ilk denetime geçer;
      // yıkıcı "Evet" düğmesi varsayılan odakta olmaz.
      const box = el.id === 'workout-overlay' ? el : el.querySelector('[role="dialog"]');
      if (box) setTimeout(() => { if (!box.contains(document.activeElement)) box.focus({ preventScroll: true }); }, 0);
    } else {
      // Önce arka planı etkinleştir: `inert` kalkmadan odak verilemez.
      syncInert();
      const op = el._a11yOpener; el._a11yOpener = null;
      if (op && document.contains(op)) setTimeout(() => { if (!op.closest('[inert]')) op.focus({ preventScroll: true }); }, 0);
    }
  }

  // ── Klavye ──────────────────────────────────────────────────
  document.addEventListener('keydown', async e => {
    const t = e.target;
    // Enter / Boşluk: yerel olmayan "düğme"leri tıkla
    if ((e.key === 'Enter' || e.key === ' ') && t instanceof Element &&
        !NATIVE.has(t.tagName) && (t.getAttribute('role') === 'button' || t.getAttribute('role') === 'switch') &&
        !t.classList.contains('dex-drag-handle')) {
      e.preventDefault();
      t.click();
      return;
    }
    // Satır sırası: yukarı/aşağı ok
    if ((e.key === 'ArrowUp' || e.key === 'ArrowDown') && t instanceof Element && t.classList.contains('dex-drag-handle')) {
      e.preventDefault();
      const from = parseInt(t.dataset.drag, 10);
      const to = from + (e.key === 'ArrowUp' ? -1 : 1);
      const n = document.querySelectorAll('#dex-list .dex-item').length;
      if (to < 0 || to >= n) return;
      await moveDexItem(from, to);
      // Liste yeniden çizildi; gözlemci henüz yeni tutamaçları işaretlemedi (odaklanabilir değiller)
      const list = document.getElementById('dex-list');
      if (list) enhanceTree(list);
      document.querySelector(`.dex-drag-handle[data-drag="${to}"]`)?.focus();
      return;
    }
    if (e.key === 'Escape') {
      const open = layers(); const top = open[open.length - 1];
      if (top && top.classList.contains('modal-backdrop') && !NO_ESCAPE.has(top.id)) { e.preventDefault(); closeModal(top.id); }
    }
  });

  // ── Gözlemci ────────────────────────────────────────────────
  const pendingRoots = new Set(), pendingState = new Set(), pendingLayers = new Set();
  let scheduled = false;
  function flush() {
    scheduled = false;
    const roots = [...pendingRoots]; pendingRoots.clear();
    const states = [...pendingState]; pendingState.clear();
    const lyrs = [...pendingLayers]; pendingLayers.clear();
    roots.forEach(r => { if (r.isConnected) enhanceTree(r); });
    states.forEach(el => { if (el.isConnected) syncState(el); });
    lyrs.forEach(onLayerToggle);
  }
  // rAF DEĞİL: sekme arka plandayken rAF durur ve işaretleme hiç güncellenmezdi.
  function schedule() { if (!scheduled) { scheduled = true; queueMicrotask(flush); } }

  const mo = new MutationObserver(muts => {
    for (const m of muts) {
      if (m.type === 'childList') {
        m.addedNodes.forEach(n => { if (n.nodeType === 1) pendingRoots.add(n); });
      } else if (m.type === 'attributes' && m.attributeName === 'class') {
        const t = m.target;
        if (t.matches && (t.matches('.modal-backdrop') || t.id === 'workout-overlay')) pendingLayers.add(t);
        else pendingState.add(t);
      }
    }
    if (pendingRoots.size || pendingState.size || pendingLayers.size) schedule();
  });

  function start() {
    setupDialogs();
    enhanceTree(document);
    mo.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['class'] });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
