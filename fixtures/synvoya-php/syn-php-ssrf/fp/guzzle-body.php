<?php
use GuzzleHttp\Client;

// Request input in the options (form body), the URL from configuration: not SSRF.
function verify($request, $config) {
    $client = new Client();
    return $client->post($config->get('recaptcha.domain'), [
        'form_params' => ['response' => $request->input('g-recaptcha-response')],
    ]);
}
