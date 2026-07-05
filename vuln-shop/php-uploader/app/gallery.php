<?php
// gallery.php — product-gallery handler.
// Stronger filter: it checks the file's MAGIC BYTES via getimagesize(), so a
// plain webshell (no image header) is rejected. It still uses a blacklist for
// the extension.
// VULN: getimagesize() only inspects the first bytes, so a POLYGLOT that starts
// with a real image header (e.g. "GIF89a") but continues with PHP passes the
// check; named shell.phtml, Apache then executes it. Magic-byte checks do not
// stop code execution.
if (empty($_FILES['file']['name'])) { http_response_code(400); exit('no file'); }
$name = basename($_FILES['file']['name']);
$ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));
$blocked = ['php', 'php3', 'php4', 'php5'];
header('Content-Type: text/plain');
if (in_array($ext, $blocked, true)) { http_response_code(400); exit("blocked extension: .$ext\n"); }
if (@getimagesize($_FILES['file']['tmp_name']) === false) {
    http_response_code(400); exit("not a valid image (magic bytes failed)\n");
}
$dest = __DIR__ . '/gallery/' . $name;
if (!move_uploaded_file($_FILES['file']['tmp_name'], $dest)) { http_response_code(500); exit('save failed'); }
echo "saved: /gallery/$name\n";
echo "url:   gallery/" . rawurlencode($name) . "\n";
