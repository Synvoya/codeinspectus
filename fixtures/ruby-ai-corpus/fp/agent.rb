require "json"
require "open3"

ALLOWED_COMMANDS = ["pwd", "git status"].freeze

def safe_action_dispatch(tool_call)
  arguments = JSON.parse(tool_call.function.arguments)
  action = arguments.fetch("action")
  { "read_file" => method(:read_file), "list_files" => method(:list_files) }.fetch(action).call(arguments)
end

def argv_without_a_shell(tool_call)
  arguments = JSON.parse(tool_call.function.arguments)
  path = arguments.fetch("path")
  system("printf", "%s", path)
end

def checked_allowlist(tool_call)
  command = JSON.parse(tool_call.function.arguments).fetch("command")
  return unless ALLOWED_COMMANDS.include?(command)

  system(command)
end

def checked_approval(tool_call, approved)
  command = JSON.parse(tool_call.function.arguments).fetch("command")
  return unless approved

  Open3.capture3(command)
end

def validated_replacement(tool_call)
  command = JSON.parse(tool_call.function.arguments).fetch("command")
  safe_command = validate_command(command)
  IO.popen(safe_command)
end

def generic_arguments(output)
  command = JSON.parse(output.arguments).fetch("command")
  system(command)
end

def decoys(tool_call)
  text = "system(tool_call.function.arguments)"
  # Open3.capture3(tool_call.function.arguments)
  system("pwd")
end
