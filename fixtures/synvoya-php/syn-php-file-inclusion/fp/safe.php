<?php
$page = basename($_GET['page']);
include __DIR__ . '/pages/' . $page . '.php';
$allowed = ['home', 'about'];
include 'pages/home.php';
require_once __DIR__ . '/vendor/autoload.php';
$template = get_template_part_path('single');
include $template;
