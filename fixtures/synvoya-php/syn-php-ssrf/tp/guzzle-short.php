<?php
namespace App\Services;

use GuzzleHttp\Client;
use Symfony\Contracts\HttpClient\HttpClientInterface;

// Re-triage 2: short-name Guzzle client and class-property clients typed as HTTP clients.
function t7() { $c = new Client(['timeout' => 5]); return $c->get($_GET['url']); }
class Svc {
    private Client $client;
    function f($request) { return $this->client->get($request->input('url')); }
}
class Svc2 {
    public function __construct(private HttpClientInterface $http) {}
    function f($request) { return $this->http->request('GET', $request->input('url')); }
}
class Svc3 {
    protected $guzzle;
    public function __construct(Client $guzzle) { $this->guzzle = $guzzle; }
    function f() { return $this->guzzle->post($_POST['hook']); }
}
