<?php

function executeSafeAction($toolCall): void
{
    $args = json_decode($toolCall->function->arguments, true);
    $action = $args['action'];
    if ($action !== 'git-status') {
        throw new RuntimeException('Unsupported action');
    }

    $process = proc_open(['git', 'status'], [], $pipes);
    if (is_resource($process)) {
        proc_close($process);
    }
}
