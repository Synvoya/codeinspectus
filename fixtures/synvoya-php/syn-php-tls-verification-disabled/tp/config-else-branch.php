<?php
// Polarity: the then-branch of a configuration check keeps verification; the disable in an if that has an
// else branch is not treated as opt-in (the rule only trusts a plain if whose body is the opt-in).
function client($strict) {
    $ch = curl_init();
    if ($strict) {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    } else {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    }
    return $ch;
}
