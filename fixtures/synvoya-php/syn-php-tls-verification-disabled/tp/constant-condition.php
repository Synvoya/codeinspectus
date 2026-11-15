<?php
// A condition made only of literals and constants is not a configuration choice.
function fetch_feed($ch) {
    if (true) {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    }
    if (DEBUG === DEBUG) {
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    }
}
