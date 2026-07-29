package example;

import com.openai.models.chat.completions.ChatCompletionMessageToolCall;
import java.util.Set;

final class Agent {
    private static final Set<String> ALLOWED_COMMANDS = Set.of("status", "version");

    interface ApprovalService {
        boolean approve(String command);
    }

    void checkedAllowlist(ChatCompletionMessageToolCall.Function function) throws Exception {
        String command = function.arguments();
        if (!ALLOWED_COMMANDS.contains(command)) {
            throw new IllegalArgumentException("Command is not allowed");
        }
        new ProcessBuilder("bash", "-c", command).start();
    }

    void checkedApproval(
            ChatCompletionMessageToolCall.Function function,
            ApprovalService approvalService) throws Exception {
        String command = function.arguments();
        if (!approvalService.approve(command)) {
            return;
        }
        new ProcessBuilder("powershell.exe", "-Command", command).start();
    }

    void fixedExecutable(ChatCompletionMessageToolCall.Function function) throws Exception {
        String ignoredModelValue = function.arguments();
        new ProcessBuilder("git", "status", "--short").start();
    }

    void notStarted(ChatCompletionMessageToolCall.Function function) {
        String command = function.arguments();
        ProcessBuilder unused = new ProcessBuilder("sh", "-c", command);
    }

    void nonModel(String requestCommand) throws Exception {
        new ProcessBuilder("sh", "-c", requestCommand).start();
    }
}
