package main

import (
	"context"
	"encoding/json"
	"os/exec"

	"github.com/openai/openai-go/v3"
)

type commandArgs struct {
	Action string `json:"action"`
}

func decodeAction(raw string) (commandArgs, error) {
	var args commandArgs
	err := json.Unmarshal([]byte(raw), &args)
	return args, err
}

func executeAllowed(ctx context.Context, action string) error {
	if action != "test" {
		return nil
	}
	return exec.CommandContext(ctx, "go", "test", "./...").Run()
}

func fixed(ctx context.Context) error {
	client := openai.NewClient()
	response, err := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{})
	if err != nil {
		return err
	}
	raw := response.Choices[0].Message.ToolCalls[0].Function.Arguments
	args, err := decodeAction(raw)
	if err != nil {
		return err
	}
	return executeAllowed(ctx, args.Action)
}
