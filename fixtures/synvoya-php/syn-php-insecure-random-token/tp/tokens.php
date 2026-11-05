<?php
$token = md5(uniqid(rand(), true));
$resetCode = mt_rand(100000, 999999);
$_SESSION['csrf_token'] = sha1(uniqid());
$data = ['api_key' => md5(mt_rand())];
function generate_token() {
    return substr(str_shuffle('abcdefghijklmnopqrstuvwxyz0123456789'), 0, 32);
}
