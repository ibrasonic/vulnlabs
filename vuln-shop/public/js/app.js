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

// VULN: secret in bundle
window.__NORTHWIND__ = {
  apiBase: '/api',
  shopifyKey: 'sk_test_NORTHWIND_DEBUG_4242424242424242',
  release: '2026.06.05-debug'
};
