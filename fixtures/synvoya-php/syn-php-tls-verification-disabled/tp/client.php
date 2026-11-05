<?php
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt_array($ch, [CURLOPT_URL => $url, CURLOPT_SSL_VERIFYPEER => FALSE]);
$response = wp_remote_post( $url, array( 'body' => $body, 'sslverify' => false ) );
$client = new \GuzzleHttp\Client(['base_uri' => $base, 'verify' => false]);
$context = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
$res = Http::withoutVerifying()->get($url);
