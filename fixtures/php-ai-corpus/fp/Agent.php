<?php

function approved($toolCall, bool $approved): void
{
    $args = json_decode($toolCall->function->arguments, true);
    $command = $args['command'];
    if (!$approved) {
        return;
    }
    exec($command);
}

function fullAllowlist($toolCall, array $allowedCommands): void
{
    $args = json_decode($toolCall->function->arguments, true);
    $command = $args['command'];
    if (!in_array($command, $allowedCommands, true)) {
        throw new RuntimeException('Not allowed');
    }
    system($command);
}

function validatedReplacement($toolCall): void
{
    $args = json_decode($toolCall->function->arguments, true);
    $command = $args['command'];
    $validatedCommand = validateAgainstSchema($command);
    shell_exec($validatedCommand);
}

function nonModel(string $command): void
{
    passthru($command);
}

function configuredOnly($toolCall): array
{
    $args = json_decode($toolCall->function->arguments, true);
    return ['command' => $args['command']];
}
