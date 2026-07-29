<?php

function direct($toolCall): void
{
    $arguments = json_decode($toolCall->function->arguments, true);
    $command = $arguments['command'];
    exec($command);
}

function readCommand(string $arguments): string
{
    $decoded = json_decode($arguments, true);
    return $decoded['script'];
}

function helper($toolCall): void
{
    $command = readCommand($toolCall->function->arguments);
    system($command);
}

class Agent
{
    public function handleSingleToolCall($toolCall): void
    {
        $functionMap = [
            'executeShellCommand' => [$this, 'executeShellCommand'],
        ];
        $name = $toolCall->function->name;
        $args = json_decode($toolCall->function->arguments, true);
        $func = $functionMap[$name];
        $func(...$args);
    }

    public function executeShellCommand(string $command): void
    {
        $allowedCommands = ['git', 'php'];
        $commandName = explode(' ', $command)[0];
        if (!in_array($commandName, $allowedCommands, true)) {
            throw new RuntimeException('Not allowed');
        }
        shell_exec($command);
    }
}
