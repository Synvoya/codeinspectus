<?php
$pack = sanitize_text_field( $_POST['pack'] );
if ( in_array( $pack, $necessary_packages, true ) ) {
    $file = $packages_dir . $pack . '/init.php';
    include_once $file;
}
