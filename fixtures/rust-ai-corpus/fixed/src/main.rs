use async_openai::types::ChatCompletionMessageToolCall;
use std::process::Command;

fn fixed(tool_call: &ChatCompletionMessageToolCall) {
    let args: serde_json::Value = serde_json::from_str(&tool_call.function.arguments).unwrap();
    let path = args["path"].as_str().unwrap();
    Command::new("git").arg("status").arg("--").arg(path).status().unwrap();
}
