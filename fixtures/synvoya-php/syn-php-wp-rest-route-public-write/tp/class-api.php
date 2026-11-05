<?php
class Shop_Settings_API {
    public function register() {
        register_rest_route( 'shop/v1', '/settings', array(
            'methods'  => WP_REST_Server::EDITABLE,
            'callback' => array( $this, 'save_settings' ),
        ) );
    }
    public function save_settings( $request ) {
        update_option( 'shop_settings', $request->get_json_params() );
    }
}
