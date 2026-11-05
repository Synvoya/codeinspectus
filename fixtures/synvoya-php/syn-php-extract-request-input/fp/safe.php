<?php
parse_str($_SERVER['QUERY_STRING'], $query);
extract(['title' => 'Home', 'items' => $items]);
$name = $_POST['name'] ?? '';
