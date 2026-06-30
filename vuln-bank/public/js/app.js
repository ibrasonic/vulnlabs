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

// VULN: DOM XSS via location.search -- `?banner=` value is read on every
// page load and assigned to innerHTML of a banner slot. Unlike the hash
// sink above, this one IS sent to the server (so it shows up in History),
// but the bug still lives entirely in the browser. Try
//   /accounts?banner=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
(function () {
  function applyBanner() {
    var p = new URLSearchParams(location.search);
    var b = p.get('banner');
    if (!b) return;
    var slot = document.getElementById('promo-banner');
    if (!slot) {
      slot = document.createElement('div');
      slot.id = 'promo-banner';
      slot.className = 'hint';
      var main = document.querySelector('main.container');
      if (main) main.prepend(slot);
    }
    // sink:
    slot.innerHTML = b;
  }
  document.addEventListener('DOMContentLoaded', applyBanner);
})();

// "Internal" telemetry endpoint URL — the bundle bakes it in.
window.__NOVA_TRUST__ = {
  apiBase: '/api',
  // VULN: secret left in client bundle (Ch 34 / secret scanning labs).
  // Treated by the support tool as a "stripe-like" key.
  internalKey: 'sk_live_NOVATRUST_DEBUG_4242424242424242',
  release: '2026.06.05-debug'
};

// VULN (B-COMP-001): vulnerable component -- jQuery 1.12.4 is loaded by
// the layout (see views/_layout.ejs). Below we pass user-controlled
// data to the `$()` selector function. In jQuery < 1.9, and again in
// jQuery 1.x via the legacy htmlPrefilter path, any string that begins
// with `<` is parsed as HTML. The new <img> is then injected and its
// onerror fires.
//
// Trigger:  /accounts?theme=<img src=x onerror=alert(1)>
(function () {
  if (typeof window.jQuery !== 'function') return;
  var $ = window.jQuery;
  function applyTheme() {
    var theme = new URLSearchParams(location.search).get('theme');
    if (!theme) return;
    var $slot = $('#theme-slot');
    if (!$slot.length) {
      $slot = $('<div id="theme-slot" class="hint"></div>');
      $('main.container').prepend($slot);
    }
    // VULN: `$(theme)` parses leading `<` as HTML and creates real DOM
    // nodes; appending the resulting <img>/<svg>/etc fires onerror.
    var $node = $(theme);
    $slot.empty().append($node);
  }
  $(applyTheme);
})();
