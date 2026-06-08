// Tiny client-side script with a deliberate DOM XSS sink and a hidden API
// token, both used in the book labs.
//
// Source map intentionally published — see /static/js/app.js.map
//# sourceMappingURL=app.js.map

// VULN: any hash fragment is dumped into innerHTML without sanitisation.
// Browse to e.g. /accounts#<img src=x onerror=alert(1)> to trigger.
(function () {
  function applyHashMessage() {
    var hash = decodeURIComponent(location.hash.slice(1) || '');
    if (!hash) return;
    var slot = document.getElementById('hash-msg');
    if (!slot) {
      slot = document.createElement('div');
      slot.id = 'hash-msg';
      slot.className = 'hint';
      document.querySelector('main.container').prepend(slot);
    }
    // sink:
    slot.innerHTML = hash;
  }
  window.addEventListener('hashchange', applyHashMessage);
  document.addEventListener('DOMContentLoaded', applyHashMessage);
})();

// "Internal" telemetry endpoint URL — the bundle bakes it in.
window.__NOVA_TRUST__ = {
  apiBase: '/api',
  // VULN: secret left in client bundle (Ch 34 / secret scanning labs).
  // Treated by the support tool as a "stripe-like" key.
  internalKey: 'sk_live_NOVATRUST_DEBUG_4242424242424242',
  release: '2026.06.05-debug'
};
