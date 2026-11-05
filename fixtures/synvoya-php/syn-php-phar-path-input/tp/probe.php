<?php
if (file_exists($_GET['file'])) {
    send_size(filesize(wp_unslash($_POST['file'])));
}
$info = getimagesize($_REQUEST['image']);
$open = is_dir('phar://' . $_GET['archive']);
