<?php
// uniqid() seeded with mt_rand() is still predictable.
function make_reset_token() {
    return sha1(uniqid(mt_rand(), true));
}
$resetToken = sha1(uniqid(mt_rand(), true));
