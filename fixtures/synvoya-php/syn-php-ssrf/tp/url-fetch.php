<?php
// URL fetches through the file API are SSRF, not path traversal; known HTTP client APIs only.
function s3() { return file_get_contents($_GET['url']); }
function s6() {
  $url = !empty($_REQUEST['uploadurl']) && preg_match('|^https?://.+$|', $_REQUEST['uploadurl']) ? $_REQUEST['uploadurl'] : null;
  copy($url, tempnam(sys_get_temp_dir(), 'upload-'));
}
function s7() { $fp = fopen('https://' . $_GET['host'] . '/status', 'r'); return $fp; }
function s8() {
  $client = new \GuzzleHttp\Client();
  return $client->get($_GET['target']);
}
function s9(\Symfony\Contracts\HttpClient\HttpClientInterface $http) {
  return $http->request('GET', $_POST['endpoint']);
}
