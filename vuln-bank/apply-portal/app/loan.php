<?php
// ===== Personal Loan — proof of income upload =====
// LEVEL 1 (EASY). VULN: no validation whatsoever. Any file, any extension, is
// moved straight under the web root, where Apache will execute .php/.phtml/etc.
$DIR = 'loan';
if ($_SERVER['REQUEST_METHOD']==='POST' && !empty($_FILES['document']['name'])) {
  $f = $_FILES['document'];
  $name = basename($f['name']);                     // keep the applicant's filename
  $dest = __DIR__."/docs/$DIR/$name";
  $ok = move_uploaded_file($f['tmp_name'], $dest);  // no checks at all
  $TITLE='Personal Loan Application'; require '_head.php'; require '_lib.php';
  if ($ok) save_panel($DIR, $name); else err('Upload failed. Please try again.');
} else {
  $TITLE='Personal Loan Application'; require '_head.php';
}
?>
<h1>Personal Loan Application</h1>
<p class="lead">Borrow from $1,000 to $50,000 with rates from 6.9% APR. Attach a
recent pay stub so we can verify your income.</p>
<div class="card">
  <h2>Proof of income</h2>
  <p>Accepted formats: PDF, JPG, PNG. Maximum 5&nbsp;MB.</p>
  <form method="post" enctype="multipart/form-data">
    <label>Full name</label><input type="text" name="applicant" placeholder="Jane Doe">
    <label>Requested amount (USD)</label><input type="text" name="amount" placeholder="10000">
    <label>Pay stub</label><input type="file" name="document">
    <button>Submit application</button>
  </form>
</div>
<p class="muted">Submitted documents are filed under <a href="docs/<?=$DIR?>/">docs/<?=$DIR?>/</a>.</p>
<?php require '_foot.php'; ?>
