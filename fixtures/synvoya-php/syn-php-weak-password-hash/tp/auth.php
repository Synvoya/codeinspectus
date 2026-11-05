<?php
$user->password = md5($_POST['password']);
$data = ['user_pass' => sha1($salt . $password)];
$user->passwordHash = hash('md5', $plainPassword);
$pass_hash = md5($newPass);
if (md5($_POST['pass']) === $row['password']) { login($row); }
$hashed_password = sha1($password);
