<?php
// random_bytes() makes the hashed input unpredictable even with uniqid() beside it.
$token = hash('sha256', uniqid() . random_bytes(32));
$nonce = bin2hex(random_bytes(8)) . mt_rand();
$data = ['csrf_token' => hash('sha256', uniqid('', true) . random_int(0, PHP_INT_MAX))];
