<?php
namespace App\Cache;

use Predis\Client;

// A short-name Client that is not Guzzle (Predis) is a cache client, not an HTTP client.
function k1() { $c = new Client(); return $c->get($_GET['key']); }
class Store {
    private Client $client;
    function f($request) { return $this->client->get($request->input('key')); }
}
