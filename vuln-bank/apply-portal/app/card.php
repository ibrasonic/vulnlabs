<?php
// ===== Credit Card — government ID upload =====
// LEVEL 2 (MEDIUM). VULN: extension BLACKLIST. The developer blocked the "php"
// numbered variants but forgot .phtml and .phar — both of which Apache still
// executes as PHP in this environment.
$DIR = 'card';
$BLOCKED = ['php','php2','php3','php4','php5','php6','php7','phps','pht','phtm',
            'shtml','cgi','pl','asp','aspx','jsp'];      // note: .phtml / .phar not listed
if ($_SERVER['REQUEST_METHOD']==='POST' && !empty($_FILES['document']['name'])) {
  $f = $_FILES['document']; $name = basename($f['name']); $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
  $TITLE='Credit Card Application'; require '_head.php'; require '_lib.php';
  if (in_array($ext, $BLOCKED, true)) {
    err('That file type is not permitted for ID documents.');
  } elseif (move_uploaded_file($f['tmp_name'], __DIR__."/docs/$DIR/$name")) {
    save_panel($DIR, $name);
  } else { err('Upload failed. Please try again.'); }
} else {
  $TITLE='Credit Card Application'; require '_head.php';
}
?>
<h1>Credit Card Application</h1>
<p class="lead">The NovaTrust Rewards Card &mdash; 2% cash back, no annual fee.
Upload a government-issued photo ID to verify your identity.</p>
<div class="card">
  <h2>Government photo ID</h2>
  <p>Accepted formats: JPG, PNG, PDF. Scripts are rejected.</p>
  <form method="post" enctype="multipart/form-data">
    <label>Full name</label><input type="text" name="applicant" placeholder="Jane Doe">
    <label>Photo ID</label><input type="file" name="document">
    <button>Submit application</button>
  </form>
</div>
<p class="muted">Submitted documents are filed under <a href="docs/<?=$DIR?>/">docs/<?=$DIR?>/</a>.</p>
<?php require '_foot.php'; ?>
