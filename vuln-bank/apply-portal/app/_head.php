<?php
// Shared chrome for the NovaTrust Applications Center (lab).
$TITLE = $TITLE ?? 'NovaTrust Applications Center';
$NAV = [
  'index.php'    => 'Home',
  'loan.php'     => 'Personal Loan',
  'card.php'     => 'Credit Card',
  'mortgage.php' => 'Mortgage',
  'verify.php'   => 'Identity Verification',
  'dispute.php'  => 'Dispute a Charge',
];
$cur = basename($_SERVER['PHP_SELF']);
?><!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars($TITLE) ?> &mdash; NovaTrust</title>
<style>
  :root{--navy:#0d2440;--teal:#0b8a7a;--ink:#1a2330;--muted:#5a6b7b;--line:#d7dee6;--bg:#f4f7fa}
  *{box-sizing:border-box} body{font-family:system-ui,Segoe UI,Arial;margin:0;color:var(--ink);background:var(--bg)}
  .topbar{background:var(--navy);color:#fff;display:flex;align-items:center;justify-content:space-between;padding:.8rem 1.4rem}
  .brand a{color:#fff;text-decoration:none;font-weight:700;font-size:1.15rem}
  .brand span{color:#7fd8cb;font-weight:500}
  nav a{color:#cdd8e4;text-decoration:none;margin-left:1rem;font-size:.92rem}
  nav a.active,nav a:hover{color:#fff}
  .wrap{max-width:880px;margin:1.6rem auto;padding:0 1.2rem}
  h1{font-size:1.5rem;margin:.2rem 0} .lead{color:var(--muted);margin:.2rem 0 1.2rem}
  .card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:1.2rem 1.4rem;margin:1rem 0;box-shadow:0 1px 3px rgba(13,36,64,.05)}
  .card h2{margin:.1rem 0 .3rem;font-size:1.15rem} .card p{color:var(--muted);margin:.2rem 0 .8rem;font-size:.94rem}
  label{display:block;margin:.6rem 0 .2rem;font-size:.9rem;font-weight:600}
  input[type=text],input[type=file]{width:100%;padding:.5rem;border:1px solid var(--line);border-radius:8px;background:#fff}
  button{background:var(--teal);color:#fff;border:0;padding:.55rem 1.1rem;border-radius:8px;font-weight:600;cursor:pointer;margin-top:.8rem}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
  .tile{display:block;background:#fff;border:1px solid var(--line);border-radius:12px;padding:1rem 1.2rem;text-decoration:none;color:var(--ink)}
  .tile:hover{border-color:var(--teal)} .tile b{display:block;color:var(--navy);font-size:1.05rem}
  .tile small{color:var(--muted)}
  .ok{background:#e7f6f2;border:1px solid #b6e3d8;color:#0b5a4e;padding:.7rem .9rem;border-radius:8px;white-space:pre-wrap;font-family:Consolas,monospace;font-size:.85rem}
  .err{background:#fdecea;border:1px solid #f5b7b1;color:#8a1c14;padding:.7rem .9rem;border-radius:8px}
  .muted{color:var(--muted);font-size:.85rem} code{background:#eef3f7;padding:.05rem .3rem;border-radius:4px}
  footer{color:var(--muted);font-size:.8rem;text-align:center;margin:2rem 0}
</style></head><body>
<header class="topbar">
  <div class="brand"><a href="index.php">NovaTrust <span>Applications Center</span></a></div>
  <nav>
    <?php foreach ($NAV as $navFile=>$navText): ?><a href="<?= $navFile ?>"<?= $navFile===$cur?' class="active"':'' ?>><?= $navText ?></a><?php endforeach; ?>
  </nav>
</header>
<main class="wrap">
