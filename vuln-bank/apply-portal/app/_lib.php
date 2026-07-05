<?php
// Small shared helpers for the application forms (lab).
function extof($n){ return strtolower(pathinfo($n, PATHINFO_EXTENSION)); }

function err($m){ echo '<div class="err">'.htmlspecialchars($m).'</div>'; }

// Render the "application received" panel and expose the stored document URL,
// so a reviewer (or an attacker) can browse straight to the saved file.
function save_panel($dir, $name){
  $url = "docs/$dir/".rawurlencode($name);
  $ref = strtoupper(substr(md5($name.microtime(true)), 0, 8));
  echo '<div class="ok">Application received. Reference: '.$ref."\n"
     . 'Your document was stored at: '.htmlspecialchars($url).'</div>';
  echo '<p class="muted">Reviewer link: <a href="'.htmlspecialchars($url).'">'
     . htmlspecialchars($url).'</a></p>';
}
