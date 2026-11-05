<?php
add_action( 'rest_api_init', function () {
    register_rest_route( 'shop/v1', '/products', array(
        'methods'             => 'GET',
        'callback'            => 'shop_list_products',
        'permission_callback' => '__return_true',
    ) );
    register_rest_route( 'shop/v1', '/orders/(?P<id>\d+)', array(
        'methods'             => WP_REST_Server::DELETABLE,
        'callback'            => 'shop_delete_order',
        'permission_callback' => function () { return current_user_can( 'manage_options' ); },
    ) );
} );
