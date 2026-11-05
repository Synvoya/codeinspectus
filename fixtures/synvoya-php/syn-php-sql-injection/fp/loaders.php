<?php
function show_directory() {
    global $wpdb;
    $directory = load_directory( absint( $_POST['directory_id'] ) );
    $row = get_directory_row( $_POST['directory_id'] );
    $wpdb->get_results( "SELECT * FROM t WHERE owner = " . $row['owner'] );
    $where = apply_filters( 'shop_where', '', $_POST['search'] );
    $wpdb->get_col( "SELECT ID FROM t WHERE 1=1 {$where}" );
    $parent_query = "SELECT ID FROM {$wpdb->posts} WHERE post_title LIKE %s";
    $wpdb->get_results( $wpdb->prepare( $parent_query, array( sanitize_text_field( $_POST['q'] ) ) ) );
    $slug = preg_replace( '/[^a-z0-9_-]/', '', $_GET['slug'] );
    $wpdb->get_var( "SELECT ID FROM t WHERE slug = '$slug'" );
}
