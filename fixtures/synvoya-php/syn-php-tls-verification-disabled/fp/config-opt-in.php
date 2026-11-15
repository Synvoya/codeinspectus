<?php
// Verification is switched off only when the operator opted in through configuration.
class Fetcher
{
    public function open(string $url)
    {
        $ch = curl_init($url);
        if ($this->config->allowUnsafeSsl) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        }
        return $ch;
    }
}
