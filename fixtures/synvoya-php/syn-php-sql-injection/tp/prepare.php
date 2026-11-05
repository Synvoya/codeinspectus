<?php
function wp_bad_prepare() {
    global $wpdb;
    $order = $_GET['orderby'];
    return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM t WHERE a = %s ORDER BY $order", 'x' ) );
}
