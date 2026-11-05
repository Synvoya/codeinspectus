<?php
$url = $_GET['url'];
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_URL, $_POST['target']);
$response = wp_remote_get( $_REQUEST['feed'] );
class Proxy {
    public function fetch(Request $request) {
        return Http::get($request->input('endpoint'));
    }
}
