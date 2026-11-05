<?php
$ch = curl_init('https://api.example.com/v1/items/' . urlencode($_GET['id']));
curl_setopt($ch, CURLOPT_URL, "https://api.example.com/search?q={$_GET['q']}");
$response = wp_safe_remote_get( $_REQUEST['feed'] );
$response = wp_remote_get( 'https://example.org/' . $_GET['path'] );
class Proxy {
    public function fetch(Request $request) {
        return Http::get('https://status.example.com/' . $request->input('id'));
    }
    public function forward(Request $request) {
        return $this->client->request('GET', '/v1/items/' . $request->query('id'));
    }
}
$cache->get($_GET['key']);
