<?php
function shop_delete_order( $request ) {
    wp_delete_post( (int) $request->get_param( 'id' ), true );
}
add_action( 'rest_api_init', function () {
    register_rest_route( 'shop/v1', '/orders/(?P<id>\d+)', array(
        'methods'             => 'DELETE',
        'callback'            => 'shop_delete_order',
        'permission_callback' => '__return_true',
    ) );
    register_rest_route( 'shop/v1', '/notes', [
        'permission_callback' => function () { return true; },
        'methods'             => 'POST',
        'callback'            => function ( $request ) { return add_post_meta( 1, 'note', $request['note'] ); },
    ] );
} );
