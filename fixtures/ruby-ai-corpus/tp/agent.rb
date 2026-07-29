require "json"
require "open3"

def direct_execution(tool_call)
  raw = tool_call.function.arguments
  parsed = JSON.parse(raw)
  command = parsed.fetch("command")
  system(command)
end

def run_command(command)
  Open3.capture3(command)
end

def wrapped_execution(tool_call)
  raw = tool_call.function.arguments
  parsed = JSON.parse(raw)
  command = parsed[:script]
  run_command(command)
end

def parse_command(raw)
  JSON.parse(raw).fetch("command")
end

def responses_execution(item)
  return unless item.is_a?(OpenAI::Models::Responses::ResponseFunctionToolCall)

  command = parse_command(item.arguments)
  Kernel.system("bash", "-c", command)
end
