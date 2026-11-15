/**
 * 4.1 M4: the regex analyzers mask comments from the parser's comment ranges. Their own character
 * scanners read the `/*` inside a regex literal such as `/\/*\/` (or inside JSX text) as the start of a
 * block comment and blanked the rest of the file, hiding every later sink. A file the parser cannot
 * read keeps the scanner's masking. Each case runs a control without the decoy line first.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import type { Finding } from "../types.js";
import { runApiBoundaryChecks } from "./api-boundary.js";
import { runLlmDynamicExecutionCheck } from "./llm-dynamic-execution.js";
import { runSecurityControlChecks } from "./security-controls.js";
import { runUnsafeToolExecutionCheck } from "./unsafe-tool-execution.js";

const REGEX_LITERAL = "const SLASH_STAR = /\\/*/;";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function project(file: string, lines: readonly string[]): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codeinspectus-comment-mask-"));
  directories.push(directory);
  await writeFile(join(directory, file), `${lines.join("\n")}\n`);
  return directory;
}

type Run = (target: string) => Promise<Finding[]>;

/** The rule's start lines without the decoy, then with the decoy as line 1 (every line moves down one). */
async function withDecoy(run: Run, rule: string, file: string, decoy: string, body: readonly string[]) {
  const lines = async (target: string) =>
    (await run(target)).filter((finding) => finding.rule_id === rule).map((finding) => finding.location.start_line);
  return { control: await lines(await project(file, body)), decoyed: await lines(await project(file, [decoy, ...body])) };
}

const MODEL_EVAL = [
  "import OpenAI from \"openai\";",
  "const openai = new OpenAI();",
  "export async function run(prompt: string) {",
  "  const response = await openai.responses.create({ model: \"gpt-5\", input: prompt });",
  "  // eval(response.output_text) in a comment is not a sink",
  "  return eval(response.output_text);",
  "}",
];

const TOOL_SHELL = [
  "import * as childProcess from \"node:child_process\";",
  "const response = await openai.chat.completions.create({ tools });",
  "const toolCall = response.choices[0].message.tool_calls[0];",
  "const parsed = JSON.parse(toolCall.function.arguments);",
  "// childProcess.exec(parsed.command) in a comment is not a sink",
  "childProcess.execSync(parsed.command);",
];

const ERROR_RESPONSE = [
  "export async function POST(request: Request) {",
  "  try {",
  "    await request.json();",
  "  } catch (error) {",
  "    return Response.json({ error: error instanceof Error ? error.message : String(error) }, { status: 500 });",
  "  }",
  "}",
];

const INSECURE_COOKIE = [
  "response.cookie(\"refresh_token\", refreshToken, {",
  "  httpOnly: false,",
  "  secure: true,",
  "  sameSite: \"strict\",",
  "});",
];

const securityControls: Run = async (target) => (await runSecurityControlChecks(target)).findings;

describe("regex analyzers mask comments from parser ranges (4.1 M4)", () => {
  test.each([
    ["llm-dynamic-execution", runLlmDynamicExecutionCheck, "ci-ai-llm-output-dynamic-execution", "run.ts", MODEL_EVAL, 6],
    ["unsafe-tool-execution", runUnsafeToolExecutionCheck, "ci-ai-llm-tool-argument-command-execution", "tool.ts", TOOL_SHELL, 6],
    ["api-boundary", runApiBoundaryChecks, "ci-ai-client-error-leak", "route.ts", ERROR_RESPONSE, 5],
    ["security-controls", securityControls, "ci-ai-insecure-session-cookie", "app.ts", INSECURE_COOKIE, 1],
  ] as const)("%s: a regex literal holding /* no longer hides the sink", async (_name, run, rule, file, body, line) => {
    expect(await withDecoy(run, rule, file, REGEX_LITERAL, body)).toEqual({ control: [line], decoyed: [line + 1] });
  });

  test("llm-dynamic-execution: JSX text holding /* is not a comment", async () => {
    const decoy = "export const Note = () => <p>/* draft</p>;";
    expect(await withDecoy(runLlmDynamicExecutionCheck, "ci-ai-llm-output-dynamic-execution", "run.tsx", decoy, MODEL_EVAL))
      .toEqual({ control: [6], decoyed: [7] });
  });

  test("a file the parser cannot read keeps the fallback masking, comments included", async () => {
    expect(await withDecoy(runLlmDynamicExecutionCheck, "ci-ai-llm-output-dynamic-execution", "run.ts", "const = ;", MODEL_EVAL))
      .toEqual({ control: [6], decoyed: [7] });
  });
});
