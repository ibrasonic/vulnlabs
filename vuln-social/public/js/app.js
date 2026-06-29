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

  // VULN: DOM XSS via window.name and document.referrer. Both sources flow
  // into the same welcome banner slot via innerHTML, with no sanitisation.
  // window.name persists across same-tab navigations -- an attacker page
  // sets `window.name = "<img src=x onerror=...>"; location = 'http://victim'`
  // and the payload fires on the victim page. document.referrer fires when
  // the user arrives via a link from an attacker page whose URL itself
  // contains HTML (rare but real on path-segment-XSS sites).
  function bootNameRefererSink() {
    var slot = document.getElementById('dom-xss-slot');
    if (!slot) return;
    var n = '';
    try { n = window.name || ''; } catch (e) {}
    var r = '';
    try { r = document.referrer || ''; } catch (e) {}
    if (n && n.length > 1 && /<|on\w+=/i.test(n)) {
      slot.innerHTML = n;
      return;
    }
    if (r && /<|on\w+=/i.test(r)) {
      slot.innerHTML = '<p>Welcome back via ' + r + '</p>';
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
      // VULN: every broadcast `msg` is rendered to a notification slot
      // via innerHTML. Any client can emit `broadcast` (sockets.js has no
      // auth on the event), so any connected attacker can XSS every
      // currently-connected user in real time. Even cross-origin: the
      // socket.io CORS allows `origin: '*'` (V-SOC-050), so an attacker
      // page just calls `io('http://127.0.0.1:3003').emit('broadcast',
      // {msg:'<img src=x onerror=alert(1)>'})`.
      s.on('broadcast', function (m) {
        console.log('[pulse-broadcast]', m);
        var slot = document.getElementById('ws-notif');
        if (!slot) {
          slot = document.createElement('div');
          slot.id = 'ws-notif';
          slot.className = 'hint';
          var main = document.querySelector('main.container');
          if (main) main.prepend(slot);
        }
        slot.innerHTML = (m && m.msg) ? String(m.msg) : '';
      });
    } catch (e) { console.error(e); }
  }

  document.addEventListener('DOMContentLoaded', function () {
    bootDomSink();
    bootNameRefererSink();
    bootJqProtoPollution();
    bootSocket();
  });
})();
//# sourceMappingURL=app.js.map
