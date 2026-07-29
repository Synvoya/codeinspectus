package example;

import com.openai.models.chat.completions.ChatCompletionMessageToolCall;

final class Agent {
    void execute(ChatCompletionMessageToolCall.Function function) throws Exception {
        String requestedAction = function.arguments();
        if ("status".equals(requestedAction)) {
            new ProcessBuilder("git", "status", "--short").start();
        } else if ("java-version".equals(requestedAction)) {
            new ProcessBuilder("java", "-version").start();
        } else {
            throw new IllegalArgumentException("Unsupported action");
        }
    }
}
