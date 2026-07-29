using OpenAI.Chat;
using System.Diagnostics;
using System.Text.Json;

static void Execute(ChatToolCall toolCall)
{
    var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(toolCall.FunctionArguments);
    var action = parsed["action"];
    if (action != "git-status") throw new InvalidOperationException();

    var info = new ProcessStartInfo { FileName = "git", UseShellExecute = false };
    info.ArgumentList.Add("status");
    Process.Start(info);
}
