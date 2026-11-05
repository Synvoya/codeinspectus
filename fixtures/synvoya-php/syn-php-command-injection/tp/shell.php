<?php
$host = $_GET['host'];
system("ping -c 1 " . $host);
$out = shell_exec("nslookup " . $_POST['domain']);
passthru("convert " . $_REQUEST['file'] . " out.png");
$listing = `ls {$_GET['dir']}`;
