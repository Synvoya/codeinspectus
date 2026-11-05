<?php
add_action( 'wp_ajax_myplugin_save', 'myplugin_save' );
function myplugin_save() {
    update_option( 'myplugin_settings', wp_unslash( $_POST['settings'] ) );
    wp_send_json_success();
}
class MyPlugin_Admin {
    public function __construct() {
        add_action( 'wp_ajax_nopriv_myplugin_vote', array( $this, 'vote' ) );
    }
    public function vote() {
        global $wpdb;
        $wpdb->insert( $wpdb->prefix . 'votes', array( 'post' => absint( $_POST['post'] ) ) );
    }
}
