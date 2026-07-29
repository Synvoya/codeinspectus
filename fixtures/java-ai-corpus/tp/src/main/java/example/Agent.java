package example;

import com.openai.models.chat.completions.ChatCompletionMessageToolCall;

final class Agent {
    private String extractCommand(String raw) {
        int separator = raw.indexOf(':');
        return separator >= 0 ? raw.substring(separator + 1) : raw;
    }

    private void runShell(String command) throws Exception {
        new ProcessBuilder("bash", "-c", command).start();
    }

    void direct(ChatCompletionMessageToolCall.Function function) throws Exception {
        String command = function.arguments();
        new ProcessBuilder("sh", "-c", command).start();
    }

    void parsed(ChatCompletionMessageToolCall.Function function) throws Exception {
        String raw = function.arguments();
        String command = extractCommand(raw);
        ProcessBuilder builder = new ProcessBuilder(
                "powershell.exe", "-NoProfile", "-Command", command);
        builder.start();
    }

    void wrapped(ChatCompletionMessageToolCall.Function function) throws Exception {
        String raw = function.arguments();
        String command = extractCommand(raw);
        runShell(command);
    }
}
