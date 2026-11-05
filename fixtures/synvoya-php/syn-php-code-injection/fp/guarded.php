<?php
$format = $_GET['format'];
$items = array_map(function ($item) use ($format) { return render_item($item, $format); }, $list);
$names = array_map(fn($u) => $u->name . $format, $users);
$cb = sanitize_text_field( $_POST['callback'] );
if ( ! in_array( $cb, $allowed_callbacks, true ) ) {
    wp_die();
}
$data = call_user_func( $cb );
