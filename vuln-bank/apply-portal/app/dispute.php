<?php
// ===== Dispute a Charge — receipt upload =====
// LEVEL 5 (VERY ADVANCED). VULN: the script blacklist here is thorough — every
// PHP/ASP/JSP variant is rejected, so no script extension gets through. BUT the
// upload directory inherits "AllowOverride All", and .htaccess itself is not a
// script, so it passes. Upload a .htaccess that tells Apache to run .jpg as PHP,
// then upload a .jpg webshell. No script extension was ever needed.
$DIR = 'dispute';
$BLOCKED = ['php','php2','php3','php4','php5','php6','php7','phps','pht','phtm',
            'phtml','phar','asp','aspx','jsp','jspx','cgi','pl','py','sh',
            'exe','shtml','svg','html','htm'];
if ($_SERVER['REQUEST_METHOD']==='POST' && !empty($_FILES['document']['name'])) {
  $f = $_FILES['document']; $name = basename($f['name']); $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
  $TITLE='Dispute a Charge'; require '_head.php'; require '_lib.php';
  if (in_array($ext, $BLOCKED, true)) {                   // .htaccess has ext "htaccess" -> not blocked
    err('Scripts are not allowed. Please upload a receipt image or PDF.');
  } elseif (move_uploaded_file($f['tmp_name'], __DIR__."/docs/$DIR/$name")) {
    save_panel($DIR, $name);
  } else { err('Upload failed. Please try again.'); }
} else {
  $TITLE='Dispute a Charge'; require '_head.php';
}
?>
<h1>Dispute a Charge</h1>
<p class="lead">See a transaction you do not recognise? Upload the merchant
receipt and our fraud team will investigate within 2 business days.</p>
<div class="card">
  <h2>Merchant receipt</h2>
  <p>Accepted formats: JPG, PNG, PDF. Script files are rejected.</p>
  <form method="post" enctype="multipart/form-data">
    <label>Transaction ID</label><input type="text" name="txn" placeholder="TXN-778120">
    <label>Receipt</label><input type="file" name="document">
    <button>Open dispute</button>
  </form>
</div>
<p class="muted">Submitted receipts are filed under <a href="docs/<?=$DIR?>/">docs/<?=$DIR?>/</a>.</p>
<?php require '_foot.php'; ?>
