<?php
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$rows = $pdo->query("SELECT * FROM posts WHERE slug = '" . $_POST['slug'] . "'");
$pdo->exec("DELETE FROM sessions WHERE token = '{$_COOKIE['sid']}'");
