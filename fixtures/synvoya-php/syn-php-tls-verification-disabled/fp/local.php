<?php
class Dav {
    public function client() {
        if (App::environment('local')) {
            $request = $this->http->withoutVerifying();
        }
        if (app()->isLocal()) {
            $client = new \GuzzleHttp\Client(['verify' => false]);
        }
    }
}
