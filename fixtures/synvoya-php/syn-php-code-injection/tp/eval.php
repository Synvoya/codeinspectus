<?php
eval('$x = ' . $_GET['expr'] . ';');
$fn = $_GET['callback'];
call_user_func($fn, 'arg');
$action = $_POST['action'];
$action();
assert($_GET['check']);
