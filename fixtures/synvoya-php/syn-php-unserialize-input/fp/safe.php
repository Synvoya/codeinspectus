<?php
$prefs = unserialize($_COOKIE['prefs'], ['allowed_classes' => false]);
$cart = json_decode($_POST['cart'], true);
$cached = unserialize(file_get_contents(__DIR__ . '/cache.bin'));
$opts = unserialize($row['options'], ['allowed_classes' => ['Settings']]);
