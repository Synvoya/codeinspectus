<?php
extract($_POST);
extract($_GET, EXTR_SKIP);
parse_str($_SERVER['QUERY_STRING']);
