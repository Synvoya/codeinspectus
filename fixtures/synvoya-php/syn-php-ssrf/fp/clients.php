<?php
// Re-triage S1/S2: a variable named *client is not an HTTP client.
function s1($redisClient) { return $redisClient->get($_GET['key']); }
class Cache {
  public function s2($request) { return $this->cacheClient->delete($request->input('key')); }
  public function s5($request) { return $this->client->get($request->query('key')); }
}
$readme = file_get_contents(__DIR__ . '/docs/' . basename($_GET['doc']));
