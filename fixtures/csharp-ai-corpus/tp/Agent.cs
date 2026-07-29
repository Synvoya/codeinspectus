using OpenAI.Chat;
using System.Diagnostics;
using System.Text.Json;

ChatToolCall toolCall = completion.ToolCalls[0];
var argsJson = toolCall.FunctionArguments;
var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(argsJson);
var command = parsed["command"];
Process.Start("cmd.exe", $"/c \"{command}\"");

var command2 = parsed["script"];
var processInfo = new ProcessStartInfo
{
    FileName = "powershell.exe",
    Arguments = $"-Command {command2}",
    UseShellExecute = false
};
Process.Start(processInfo);

var command3 = parsed["cmd"];
RunShell(command3);

static void RunShell(string command)
{
    Process.Start("bash", $"-c '{command}'");
}
