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

func approvedCommand(command string) bool { return command == "go test ./..." }

func guarded(ctx context.Context) error {
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
	approved := approvedCommand(args.Command)
	if !approved {
		return nil
	}
	return exec.Command("sh", "-c", args.Command).Run()
}

func allowlisted(ctx context.Context) error {
	client := openai.NewClient()
	response, _ := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{})
	raw := response.Choices[0].Message.ToolCalls[0].Function.Arguments
	args, _ := decodeCommand(raw)
	allowedCommands := map[string]struct{}{"go test ./...": {}}
	_, ok := allowedCommands[args.Command]
	if !ok {
		return nil
	}
	return exec.Command("bash", "-c", args.Command).Run()
}

func validated(ctx context.Context) error {
	client := openai.NewClient()
	response, _ := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{})
	raw := response.Choices[0].Message.ToolCalls[0].Function.Arguments
	args, _ := decodeCommand(raw)
	safeCommand, err := validateCommand(args.Command)
	if err != nil {
		return err
	}
	return exec.Command("sh", "-c", safeCommand).Run()
}

func validateCommand(command string) (string, error) { return "go test ./...", nil }

func safeSinks(ctx context.Context) error {
	client := openai.NewClient()
	response, _ := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{})
	raw := response.Choices[0].Message.ToolCalls[0].Function.Arguments
	args, _ := decodeCommand(raw)
	if err := exec.Command("git", "status", "--short").Run(); err != nil {
		return err
	}
	if err := exec.Command("python3", "-c", args.Command).Run(); err != nil {
		return err
	}
	return exec.Command("sh", "-c", "go test ./...").Run()
}

func unrelated(command string) error {
	return exec.Command("sh", "-c", command).Run()
}
