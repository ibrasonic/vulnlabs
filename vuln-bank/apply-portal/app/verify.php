<?php
// ===== Identity Verification (KYC) — selfie / ID photo upload =====
// LEVEL 4 (ADVANCED). VULN: getimagesize() must succeed AND a blacklist blocks
// the obvious script extensions. Both are defeated by a POLYGLOT: a file that
// begins with real image magic bytes (so getimagesize passes) but ends in a
// PHP payload and carries a still-executable extension such as .phtml.
$DIR = 'verify';
$BLOCKED = ['php','php2','php3','php4','php5','php6','php7','phps','pht','phtm',
            'asp','aspx','jsp','cgi','pl','shtml'];       // note: .phtml / .phar not listed
if ($_SERVER['REQUEST_METHOD']==='POST' && !empty($_FILES['document']['name'])) {
  $f = $_FILES['document']; $name = basename($f['name']); $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
  $info = @getimagesize($f['tmp_name']);                  // reads leading magic bytes
  $TITLE='Identity Verification'; require '_head.php'; require '_lib.php';
  if ($info === false) {
    err('That does not look like a photo. Please upload a JPG, PNG, or GIF.');
  } elseif (in_array($ext, $BLOCKED, true)) {
    err('Executable file types are not allowed.');
  } elseif (move_uploaded_file($f['tmp_name'], __DIR__."/docs/$DIR/$name")) {
    save_panel($DIR, $name);
  } else { err('Upload failed. Please try again.'); }
} else {
  $TITLE='Identity Verification'; require '_head.php';
}
?>
<h1>Identity Verification</h1>
<p class="lead">Final step: upload a clear selfie of yourself holding your photo
ID. Our system checks that the file is a genuine image before accepting it.</p>
<div class="card">
  <h2>Selfie with ID</h2>
  <p>Accepted formats: JPG, PNG, GIF. The file must be a real image.</p>
  <form method="post" enctype="multipart/form-data">
    <label>Applicant reference</label><input type="text" name="ref" placeholder="APP-000123">
    <label>Selfie photo</label><input type="file" name="document">
    <button>Verify identity</button>
  </form>
</div>
<p class="muted">Submitted photos are filed under <a href="docs/<?=$DIR?>/">docs/<?=$DIR?>/</a>.</p>
<?php require '_foot.php'; ?>
