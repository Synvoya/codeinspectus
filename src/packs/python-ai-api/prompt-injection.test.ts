import { describe, expect, test } from "vitest";

import { parsePythonSource } from "../python/python.js";
import type { PythonProject } from "../python/project.js";
import { runPythonPromptInjectionSink } from "./prompt-injection.js";

function project(source: string): PythonProject {
  return {
    target: "/virtual/python",
    root: "/virtual/python",
    files: [parsePythonSource("src/chat.py", source)],
  };
}

describe("Python prompt-injection sink rule", () => {
  test("flags request input in proven OpenAI instructions and Anthropic system positions", async () => {
    const findings = await runPythonPromptInjectionSink(project(`
from fastapi import FastAPI
from openai import OpenAI
import anthropic

app = FastAPI()

@app.post("/openai")
def openai_chat(request: ChatRequest):
    client = OpenAI()
    instructions = request.instructions
    return client.responses.create(
        model="gpt-4.1-mini",
        instructions=instructions,
        input=request.message,
    )

@app.post("/anthropic")
def anthropic_chat(payload: ChatRequest):
    client = anthropic.Anthropic()
    return client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        system=payload.system_prompt or "You are a support assistant.",
        messages=[{"role": "user", "content": payload.message}],
    )
`));

    expect(findings).toHaveLength(2);
    expect(findings.every((finding) =>
      finding.rule_id === "ci-python-prompt-injection-sink" &&
      finding.severity === "medium" &&
      finding.confidence === "medium" &&
      finding.cwe.join(",") === "CWE-1427" &&
      finding.owasp_llm?.join(",") === "LLM01:2025"
    )).toBe(true);
  });

  test("raises severity when request prompt data shares the call with tool access", async () => {
    const findings = await runPythonPromptInjectionSink(project(`
from fastapi import APIRouter
from openai import AsyncOpenAI
from anthropic import AsyncAnthropic

router = APIRouter()
AVAILABLE_TOOLS = [{"name": "send_email"}]

@router.post("/research")
async def research(request: ResearchRequest):
    client = AsyncOpenAI()
    return await client.responses.create(
        model="gpt-4.1",
        instructions="Research the supplied topic.",
        input=request.topic,
        tools=[{"type": "web_search_preview"}],
    )

@router.post("/act")
async def act(payload: AgentRequest):
    client = AsyncAnthropic()
    return await client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        system=payload.instructions,
        messages=[{"role": "user", "content": payload.message}],
        tools=AVAILABLE_TOOLS,
    )
`));

    expect(findings).toHaveLength(2);
    expect(findings.every((finding) =>
      finding.severity === "high" &&
      finding.confidence === "medium" &&
      finding.owasp_llm?.join(",") === "LLM01:2025,LLM06:2025"
    )).toBe(true);
  });

  test("keeps ordinary user input without tools and statically empty tool sets silent", async () => {
    const findings = await runPythonPromptInjectionSink(project(`
from fastapi import FastAPI
from openai import OpenAI
from anthropic import Anthropic

app = FastAPI()

@app.post("/safe-openai")
def safe_openai(request: ChatRequest):
    client = OpenAI()
    return client.responses.create(
        model="gpt-4.1-mini",
        instructions="You are a support assistant.",
        input=request.message,
        tools=[],
    )

@app.post("/safe-anthropic")
def safe_anthropic(payload: ChatRequest):
    client = Anthropic()
    return client.messages.create(
        model=payload.model,
        max_tokens=512,
        system="You are a support assistant.",
        messages=payload.messages,
        tools=None,
    )
`));

    expect(findings).toEqual([]);
  });

  test("fails closed for helper parameters, spreads, lookalikes, shadowing, and malformed source", async () => {
    const helper = await runPythonPromptInjectionSink(project(`
from openai import OpenAI

def offline_job(instructions: str):
    client = OpenAI()
    return client.responses.create(instructions=instructions, input="hello")
`));
    const spread = await runPythonPromptInjectionSink(project(`
from fastapi import FastAPI
from openai import OpenAI
app = FastAPI()
@app.post("/chat")
def chat(request: ChatRequest, options):
    client = OpenAI()
    return client.responses.create(instructions=request.instructions, input=request.message, **options)
`));
    const lookalike = await runPythonPromptInjectionSink(project(`
from fastapi import FastAPI
app = FastAPI()
class OpenAI:
    pass
@app.post("/chat")
def chat(request: ChatRequest):
    client = OpenAI()
    return client.responses.create(instructions=request.instructions, input=request.message)
`));
    const shadowed = await runPythonPromptInjectionSink(project(`
from fastapi import FastAPI
from anthropic import Anthropic
app = FastAPI()
class Anthropic:
    pass
@app.post("/chat")
def chat(request: ChatRequest):
    client = Anthropic()
    return client.messages.create(system=request.instructions, messages=request.messages)
`));
    const malformed = await runPythonPromptInjectionSink(project(`
from fastapi import FastAPI
from openai import OpenAI
app = FastAPI()
@app.post("/chat")
def chat(request: ChatRequest):
    client = OpenAI()
    return client.responses.create(instructions=request.instructions,
`));

    expect(helper).toEqual([]);
    expect(spread).toEqual([]);
    expect(lookalike).toEqual([]);
    expect(shadowed).toEqual([]);
    expect(malformed).toEqual([]);
  });

  test("rejects conditionally imported SDK bindings", async () => {
    const findings = await runPythonPromptInjectionSink(project(`
from fastapi import FastAPI
app = FastAPI()
if enabled:
    from openai import OpenAI
@app.post("/chat")
def chat(request: ChatRequest):
    client = OpenAI()
    return client.responses.create(instructions=request.instructions, input=request.message)
`));

    expect(findings).toEqual([]);
  });
});
