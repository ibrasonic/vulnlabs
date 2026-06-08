// public/js/app.js — client glue + deliberate sinks.
(function () {
  // VULN: secret in client bundle.
  window.__PULSE__ = {
    sentryKey: 'pk_test_PULSE_SENTRY_DEBUG_4848484848484848',
    geminiKeyHint: 'AIza_demo_LEAKED_KEY_FROM_BUNDLE',
    build: '2026.06.03'
  };

  // VULN: DOM XSS via location.hash injected into innerHTML.
  function bootDomSink() {
    var slot = document.getElementById('dom-xss-slot');
    if (!slot) return;
    if (location.hash && location.hash.length > 1) {
      try {
        slot.innerHTML = decodeURIComponent(location.hash.slice(1));
      } catch (e) {}
    }
  }

  // VULN: jQuery 1.12.4 $.extend(true, {}, JSON.parse(payload)) prototype pollution
  // demonstrator -- read ?pp= in URL.
  function bootJqProtoPollution() {
    if (!window.jQuery) return;
    var u = new URLSearchParams(location.search);
    var pp = u.get('pp');
    if (!pp) return;
    try { jQuery.extend(true, {}, JSON.parse(pp)); } catch (e) {}
  }

  // Realtime: connect without auth.
  function bootSocket() {
    if (!window.io) return;
    try {
      var s = io({ transports: ['websocket', 'polling'] });
      window.__PULSE__.socket = s;
      s.on('hello', function (h) { console.log('[pulse-ws]', h); });
      s.on('broadcast', function (m) { console.log('[pulse-broadcast]', m); });
    } catch (e) { console.error(e); }
  }

  document.addEventListener('DOMContentLoaded', function () {
    bootDomSink();
    bootJqProtoPollution();
    bootSocket();
  });
})();
//# sourceMappingURL=app.js.map
