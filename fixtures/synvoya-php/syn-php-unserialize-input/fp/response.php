<?php
function check_license( $license ) {
    $request = wp_remote_post( 'https://store.example.com/', array( 'body' => array( 'license' => $license ) ) );
    $request = wp_remote_retrieve_body( $request );
    return maybe_unserialize( $request['body'] );
}
function show_dir() {
    $directory_data = load_directory_data( $_POST['directory_id'] );
    return maybe_unserialize( $directory_data['roles'] );
}
