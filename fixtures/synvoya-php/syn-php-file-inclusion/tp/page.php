<?php
$page = $_GET['page'];
include $page . '.php';
require_once($_REQUEST['module']);
include_once 'lang/' . $_COOKIE['lang'] . '.php';
