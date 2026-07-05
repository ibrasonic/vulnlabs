<?php
// avatar.php — profile-avatar handler.
// Two filters, both real and both bypassable:
//   1) an extension BLACKLIST that only remembers "php" and friends;
//   2) a Content-Type check on the CLIENT-SUPPLIED multipart type.
// VULN: the blacklist omits .phtml/.pht (which Apache still runs, see lab.conf),
// and the Content-Type is attacker-controlled (set it to image/png in Reqlore).
// Bypass: upload shell.phtml with Content-Type: image/png -> executes.
if (empty($_FILES['file']['name'])) { http_response_code(400); exit('no file'); }
$name = basename($_FILES['file']['name']);
$ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));
$blocked = ['php', 'php3', 'php4', 'php5'];           // NOTE: phtml / pht NOT listed
header('Content-Type: text/plain');
if (in_array($ext, $blocked, true)) { http_response_code(400); exit("blocked extension: .$ext\n"); }
if (strpos((string)$_FILES['file']['type'], 'image/') !== 0) {
    http_response_code(400); exit("not an image (Content-Type was '{$_FILES['file']['type']}')\n");
}
$dest = __DIR__ . '/avatars/' . $name;
if (!move_uploaded_file($_FILES['file']['tmp_name'], $dest)) { http_response_code(500); exit('save failed'); }
echo "saved: /avatars/$name\n";
echo "url:   avatars/" . rawurlencode($name) . "\n";
