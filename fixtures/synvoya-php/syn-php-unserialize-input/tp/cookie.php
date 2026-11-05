<?php
$prefs = unserialize(base64_decode($_COOKIE['prefs']));
$cart = unserialize($_POST['cart']);
function wp_restore() {
    return maybe_unserialize( wp_unslash( $_POST['state'] ) );
}
