<?php
// Re-triage 2: stored through an intermediate variable, and salted with a key.
function w2($db, $password) { $hash = md5($password); $db->insert('users', ['pw' => $hash]); }
function w4($user, $password, $site_key) { $user->password = md5($password . $site_key); }
function w6($user, $password) { $digest = sha1($password); $user->password = $digest; $user->save(); }
