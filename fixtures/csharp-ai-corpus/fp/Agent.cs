using OpenAI.Chat;
using System.Diagnostics;
using System.Text.Json;

static string ReadCommand(ChatToolCall toolCall)
{
    var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(toolCall.FunctionArguments);
    return parsed["command"];
}

static void CheckedApproval(ChatToolCall toolCall, bool approved)
{
    var command = ReadCommand(toolCall);
    if (!approved) return;
    Process.Start("cmd.exe", $"/c {command}");
}

static void CheckedAllowlist(ChatToolCall toolCall, HashSet<string> AllowedCommands)
{
    var command = ReadCommand(toolCall);
    if (!AllowedCommands.Contains(command)) throw new InvalidOperationException();
    Process.Start("bash", $"-c {command}");
}

static void NotStarted(ChatToolCall toolCall)
{
    var command = ReadCommand(toolCall);
    var info = new ProcessStartInfo { FileName = "cmd.exe", Arguments = $"/c {command}" };
}

static void FixedExecutable(ChatToolCall toolCall)
{
    var command = ReadCommand(toolCall);
    Process.Start("git", $"status {command}");
}

static void ValidatedReplacement(ChatToolCall toolCall)
{
    var command = ReadCommand(toolCall);
    var validatedCommand = ValidateAgainstSchema(command);
    Process.Start("pwsh", $"-Command {validatedCommand}");
}

static void NonModel(string command)
{
    Process.Start("cmd.exe", $"/c {command}");
}
