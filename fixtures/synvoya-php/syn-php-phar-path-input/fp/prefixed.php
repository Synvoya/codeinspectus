<?php
$path = FM_ROOT_PATH . '/' . $_GET['p'];
if (file_exists($path)) { send_ok(); }
$size = filesize($path);
$zip_name = str_replace('phar://' . $path, '', $entry);
