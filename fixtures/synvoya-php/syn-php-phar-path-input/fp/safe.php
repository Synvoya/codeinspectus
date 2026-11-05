<?php
$name = basename($_GET['file']);
if (file_exists(__DIR__ . '/uploads/' . $name)) { send_ok(); }
if (file_exists('/var/data/' . $_GET['file'])) { send_ok(); }
if (is_dir("uploads/{$_GET['dir']}")) { send_ok(); }
$size = filesize(__FILE__);
