use async_openai::types::ChatCompletionMessageToolCall;
use bollard::exec::CreateExecOptions;
use std::process::Command;

fn approved(tool_call: &ChatCompletionMessageToolCall) {
    let args: serde_json::Value = serde_json::from_str(&tool_call.function.arguments).unwrap();
    let command = args["command"].as_str().unwrap();
    if !approve(command) { return; }
    Command::new("sh").arg("-c").arg(command).status().unwrap();
}

fn allowlisted(tool_call: &ChatCompletionMessageToolCall) {
    let args: serde_json::Value = serde_json::from_str(&tool_call.function.arguments).unwrap();
    let command = args["command"].as_str().unwrap();
    let allowed_commands = ["git status", "cargo test"];
    if !allowed_commands.contains(&command) { return; }
    Command::new("sh").arg("-c").arg(command).status().unwrap();
}

fn replaced(tool_call: &ChatCompletionMessageToolCall) {
    let command = validate_command(&tool_call.function.arguments);
    Command::new("sh").arg("-c").arg(command).status().unwrap();
}

async fn configured_only(tool_call: &ChatCompletionMessageToolCall, docker: &bollard::Docker) {
    let args: serde_json::Value = serde_json::from_str(&tool_call.function.arguments).unwrap();
    let command = args["command"].as_str().unwrap();
    let options = CreateExecOptions {
        cmd: Some(vec!["/bin/bash", "-c", command]),
        ..Default::default()
    };
    let _ = docker.create_exec("container", options).await;
}

fn fixed_executable(tool_call: &ChatCompletionMessageToolCall) {
    let args: serde_json::Value = serde_json::from_str(&tool_call.function.arguments).unwrap();
    let path = args["path"].as_str().unwrap();
    Command::new("git").arg("status").arg("--").arg(path).status().unwrap();
}

fn non_model(command: &str) {
    Command::new("sh").arg("-c").arg(command).status().unwrap();
}

fn approve(_command: &str) -> bool { true }
fn validate_command(_arguments: &str) -> &'static str { "git status" }
