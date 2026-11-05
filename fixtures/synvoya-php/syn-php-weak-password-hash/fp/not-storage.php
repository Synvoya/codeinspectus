<?php
// Re-triage W1-W3: no password is being stored or checked.
function w1($password_reset_token) { return md5($password_reset_token); }
function w2($order) { $password_hint = md5($order->id); return $password_hint; }
function w3($password_policy_json) { return 'pp_' . md5($password_policy_json); }
function w4($user) { $password_reset_key = sha1($user->email . time()); return $password_reset_key; }
$cache_key = md5('password_rules_' . $locale);
$hash = md5($_POST['password_confirmation_token']);
