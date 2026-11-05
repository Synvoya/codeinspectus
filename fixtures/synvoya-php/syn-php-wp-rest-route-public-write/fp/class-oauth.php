<?php
class Shop_OAuth_Token {
    public function register() {
        register_rest_route( 'shop/v1', '/token', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'handle_token' ),
            'permission_callback' => '__return_true',
        ) );
        register_rest_route( 'shop/v1', '/webhook', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'handle_webhook' ),
            'permission_callback' => '__return_true',
        ) );
        register_rest_route( 'shop/v1', '/external', array(
            'methods'             => 'POST',
            'callback'            => array( 'Other_Class', 'handle' ),
            'permission_callback' => '__return_true',
        ) );
    }
    public function handle_token( $request ) {
        $client = $this->find_client( $request['client_id'], $request['client_secret'] );
        return $this->issue_token( $client );
    }
    public function handle_webhook( $request ) {
        if ( ! hash_equals( hash_hmac( 'sha256', $request->get_body(), SHOP_KEY ), $request->get_header( 'x-signature' ) ) ) {
            return new WP_Error( 'forbidden' );
        }
        update_option( 'shop_last_event', time() );
    }
}
