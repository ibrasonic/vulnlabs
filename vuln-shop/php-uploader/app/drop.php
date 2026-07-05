<?php
// drop.php — support attachment handler.
// VULN: NO validation of any kind. The client's filename (extension included)
// is trusted, saved into a web-served directory, and Apache will execute it if
// it is a PHP type. Upload shell.php -> /u/shell.php?cmd=id -> RCE.
if (empty($_FILES['file']['name'])) { http_response_code(400); exit('no file'); }
$name = basename($_FILES['file']['name']);            // attacker-controlled
$dest = __DIR__ . '/u/' . $name;
if (!move_uploaded_file($_FILES['file']['tmp_name'], $dest)) { http_response_code(500); exit('save failed'); }
$url = 'u/' . rawurlencode($name);
header('Content-Type: text/plain');
echo "saved: /$url\n";
echo "url:   " . $url . "\n";
