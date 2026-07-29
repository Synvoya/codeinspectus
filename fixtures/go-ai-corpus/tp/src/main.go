package main

import (
	"context"
	"encoding/json"
	"os/exec"

	"github.com/openai/openai-go/v3"
)

type commandArgs struct {
	Command string `json:"command"`
}

func decodeCommand(raw string) (commandArgs, error) {
	var args commandArgs
	err := json.Unmarshal([]byte(raw), &args)
	return args, err
}

func runShell(command string) error {
	return exec.Command("bash", "-c", command).Run()
}

func direct(ctx context.Context) error {
	client := openai.NewClient()
	response, err := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{})
	if err != nil {
		return err
	}
	raw := response.Choices[0].Message.ToolCalls[0].Function.Arguments
	args, err := decodeCommand(raw)
	if err != nil {
		return err
	}
	return exec.Command("sh", "-c", args.Command).Run()
}

func loop(ctx context.Context) error {
	client := openai.NewClient()
	response, err := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{})
	if err != nil {
		return err
	}
	for _, toolCall := range response.Choices[0].Message.ToolCalls {
		var args commandArgs
		if err := json.Unmarshal([]byte(toolCall.Function.Arguments), &args); err != nil {
			return err
		}
		if err := exec.CommandContext(ctx, "bash", "-c", args.Command).Run(); err != nil {
			return err
		}
	}
	return nil
}

func wrapped(ctx context.Context) error {
	client := openai.NewClient()
	response, err := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{})
	if err != nil {
		return err
	}
	raw := response.Choices[0].Message.ToolCalls[0].Function.Arguments
	args, err := decodeCommand(raw)
	if err != nil {
		return err
	}
	return runShell(args.Command)
}
