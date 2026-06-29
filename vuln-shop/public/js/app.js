//# sourceMappingURL=app.js.map

// VULN: location.hash piped into innerHTML
(function () {
  function applyHashMessage() {
    var hash = decodeURIComponent(location.hash.slice(1) || '');
    if (!hash) return;
    var slot = document.getElementById('hash-msg');
    if (!slot) {
      slot = document.createElement('div');
      slot.id = 'hash-msg';
      slot.className = 'ok';
      var main = document.querySelector('main.container');
      if (main) main.prepend(slot);
    }
    slot.innerHTML = hash;  // sink
  }
  window.addEventListener('hashchange', applyHashMessage);
  document.addEventListener('DOMContentLoaded', applyHashMessage);
})();

// VULN: postMessage listener with no origin check. An attacker page that
// frames or window.opens the shop can call
//   targetWin.postMessage('<img src=x onerror=alert(1)>', '*')
// and the payload is rendered via innerHTML into a notification slot.
// Try from the browser console of any shop page:
//   window.postMessage('<img src=x onerror=alert(1)>', '*')
(function () {
  function ensureSlot() {
    var slot = document.getElementById('notif-slot');
    if (!slot) {
      slot = document.createElement('div');
      slot.id = 'notif-slot';
      slot.className = 'hint';
      var main = document.querySelector('main.container');
      if (main) main.prepend(slot);
    }
    return slot;
  }
  window.addEventListener('message', function (e) {
    // NO origin check, NO data validation.
    var s = ensureSlot();
    s.innerHTML = (typeof e.data === 'string') ? e.data
                  : (e.data && e.data.html) ? e.data.html
                  : String(e.data || '');
  });
})();

// VULN: secret in bundle
window.__NORTHWIND__ = {
  apiBase: '/api',
  shopifyKey: 'sk_test_NORTHWIND_DEBUG_4242424242424242',
  release: '2026.06.05-debug'
};
