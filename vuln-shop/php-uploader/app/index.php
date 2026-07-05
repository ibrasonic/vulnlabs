<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Northwind Media &mdash; legacy uploader</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial;max-width:860px;margin:2rem auto;padding:0 1rem;color:#1a2330}
  form{border:1px solid #d3d9e0;padding:1rem 1.2rem;margin:1rem 0;border-radius:10px;background:#f7f9fb}
  h2{margin:.1rem 0 .3rem} .muted{color:#5a6b7b;font-size:.92rem;margin:.2rem 0 .7rem}
  button{padding:.4rem .9rem} a{color:#0b6}
  header{border-bottom:2px solid #0b8;padding-bottom:.5rem}
</style></head><body>
<header><h1>Northwind Media <small class="muted">&mdash; legacy media host</small></h1></header>
<p class="muted">Internal host for support attachments, profile avatars, and product gallery images.
Files are served back from this same host.</p>

<form action="drop.php" method="post" enctype="multipart/form-data">
  <h2>Support attachment</h2>
  <p class="muted">Attach any file to a support ticket. Saved under <code>/u/</code>.</p>
  <input type="file" name="file" required> <button>Upload</button>
</form>

<form action="avatar.php" method="post" enctype="multipart/form-data">
  <h2>Profile avatar</h2>
  <p class="muted">PNG / JPG / GIF only. Saved under <code>/avatars/</code>.</p>
  <input type="file" name="file" required> <button>Upload</button>
</form>

<form action="gallery.php" method="post" enctype="multipart/form-data">
  <h2>Product gallery image</h2>
  <p class="muted">Verified images only. Saved under <code>/gallery/</code>.</p>
  <input type="file" name="file" required> <button>Upload</button>
</form>

<p class="muted">Browse stored files: <a href="u/">/u/</a> &middot;
<a href="avatars/">/avatars/</a> &middot; <a href="gallery/">/gallery/</a></p>
</body></html>
