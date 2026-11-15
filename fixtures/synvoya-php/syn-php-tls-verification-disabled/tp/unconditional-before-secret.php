<?php
// Unconditional: the API key travels over a connection whose certificate is never checked.
function charge(string $apiKey, array $payload) {
    $ch = curl_init('https://payments.example.test/v1/charges');
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $apiKey]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    return curl_exec($ch);
}
