require "json"

TOOLS = {
  "read_file" => ->(arguments) { File.read(arguments.fetch("path")) },
  "list_files" => ->(arguments) { Dir.children(arguments.fetch("path", ".")) },
}.freeze

def execute_tool(tool_call)
  arguments = JSON.parse(tool_call.function.arguments)
  tool = TOOLS.fetch(tool_call.function.name)
  tool.call(arguments)
end
