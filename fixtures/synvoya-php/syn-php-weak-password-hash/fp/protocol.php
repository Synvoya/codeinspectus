<?php
$response = $this->sendRequest('APOP', md5($secret . $password));
$ha1 = md5($username . ':' . $realm . ':' . $password);
