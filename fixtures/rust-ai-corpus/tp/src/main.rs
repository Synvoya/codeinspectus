use async_openai::types::ChatCompletionMessageToolCall;
use bollard::exec::CreateExecOptions;
use std::process::Command;

fn direct(tool_call: &ChatCompletionMessageToolCall) {
    let args: serde_json::Value = serde_json::from_str(&tool_call.function.arguments).unwrap();
    let command = args["command"].as_str().unwrap();
    Command::new("sh").arg("-c").arg(command).status().unwrap();
}

fn run_shell(command: &str) {
    std::process::Command::new("bash").arg("-c").arg(command).output().unwrap();
}

fn wrapped(tool_call: &ChatCompletionMessageToolCall) {
    let args: serde_json::Value = serde_json::from_str(&tool_call.function.arguments).unwrap();
    let command = args["script"].as_str().unwrap();
    run_shell(command);
}

async fn docker(tool_call: &ChatCompletionMessageToolCall, docker: &bollard::Docker) {
    let args: serde_json::Value = serde_json::from_str(&tool_call.function.arguments).unwrap();
    let command = args["command"].as_str().unwrap();
    let options = CreateExecOptions {
        cmd: Some(vec!["/bin/bash", "-c", command]),
        ..Default::default()
    };
    let exec = docker.create_exec("container", options).await.unwrap().id;
    docker.start_exec(&exec, None).await.unwrap();
}
