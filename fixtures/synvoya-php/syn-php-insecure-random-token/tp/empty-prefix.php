<?php
// An empty uniqid() prefix is no mitigation.
function t1() { $csrf_token = uniqid('', true); return $csrf_token; }
function t2() { $token = uniqid(); return $token; }
function t3() { $password = md5(uniqid()); return $password; }
