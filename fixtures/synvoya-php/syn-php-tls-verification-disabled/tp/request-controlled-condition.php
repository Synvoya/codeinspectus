<?php
// The "opt-in" comes from the request: any caller can switch verification off.
function fetch_remote($url) {
    $ch = curl_init($url);
    if ($_GET['insecure']) {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    }
    return curl_exec($ch);
}
