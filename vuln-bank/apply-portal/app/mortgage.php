<?php
// ===== Mortgage Pre-Approval — property appraisal upload =====
// LEVEL 3 (MEDIUM). VULN: the only check is the multipart Content-Type, which
// is supplied by the CLIENT. Spoof it to image/png (or application/pdf) and any
// filename — including shell.php — sails through.
$DIR = 'mortgage';
$ALLOWED_MIME = ['image/jpeg','image/png','image/gif','application/pdf'];
if ($_SERVER['REQUEST_METHOD']==='POST' && !empty($_FILES['document']['name'])) {
  $f = $_FILES['document']; $name = basename($f['name']);
  $TITLE='Mortgage Pre-Approval'; require '_head.php'; require '_lib.php';
  if (!in_array($f['type'], $ALLOWED_MIME, true)) {           // trusts $_FILES[..]['type']
    err('Please upload an image or PDF appraisal.');
  } elseif (move_uploaded_file($f['tmp_name'], __DIR__."/docs/$DIR/$name")) {
    save_panel($DIR, $name);
  } else { err('Upload failed. Please try again.'); }
} else {
  $TITLE='Mortgage Pre-Approval'; require '_head.php';
}
?>
<h1>Mortgage Pre-Approval</h1>
<p class="lead">Get pre-approved in 24 hours. Upload a recent property appraisal
so an underwriter can review the estimated value.</p>
<div class="card">
  <h2>Property appraisal</h2>
  <p>Accepted formats: image (JPG, PNG, GIF) or PDF. Maximum 10&nbsp;MB.</p>
  <form method="post" enctype="multipart/form-data">
    <label>Property address</label><input type="text" name="address" placeholder="12 Elm St">
    <label>Appraisal document</label><input type="file" name="document">
    <button>Submit for pre-approval</button>
  </form>
</div>
<p class="muted">Submitted documents are filed under <a href="docs/<?=$DIR?>/">docs/<?=$DIR?>/</a>.</p>
<?php require '_foot.php'; ?>
