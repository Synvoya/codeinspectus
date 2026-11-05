<?php
function lookup_orders() {
    global $wpdb;
    $status = sanitize_text_field( $_GET['status'] );
    return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders WHERE status = '$status'" );
}
