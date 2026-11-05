<?php
add_action( 'wp_ajax_myplugin_save', 'myplugin_save' );
function myplugin_save() {
    check_ajax_referer( 'myplugin_save' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error();
    }
    update_option( 'myplugin_settings', wp_unslash( $_POST['settings'] ) );
}
add_action( 'wp_ajax_myplugin_list', 'myplugin_list' );
function myplugin_list() {
    wp_send_json( get_option( 'myplugin_items' ) );
}
function myplugin_not_ajax() {
    update_option( 'myplugin_version', '1.0' );
}
class MyPlugin_Admin {
    public function __construct() {
        add_action( 'wp_ajax_myplugin_vote', array( $this, 'vote' ) );
    }
    public function vote() {
        if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'vote' ) ) {
            wp_die();
        }
        update_post_meta( absint( $_POST['post'] ), 'votes', 1 );
    }
}
