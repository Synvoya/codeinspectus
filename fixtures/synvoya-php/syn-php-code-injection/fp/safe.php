<?php
eval('$x = 1;');
$handlers = ['list' => 'show_list', 'view' => 'show_view'];
$key = $_GET['action'] === 'view' ? 'view' : 'list';
call_user_func($handlers[$key]);
$fn = 'strtoupper';
echo_value($fn('abc'));
assert(isset($_GET['check']));
$obj->method($_GET['a']);
