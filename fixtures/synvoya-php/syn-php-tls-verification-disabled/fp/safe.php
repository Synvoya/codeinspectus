<?php
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->verifySsl);
$response = wp_remote_post( $url, array( 'sslverify' => apply_filters( 'https_local_ssl_verify', false ) ) );
$client = new \GuzzleHttp\Client(['verify' => '/etc/ssl/ca.pem']);
$validator->validate($data, ['verify' => false]);
