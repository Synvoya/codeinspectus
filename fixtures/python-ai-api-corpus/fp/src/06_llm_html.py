from fastapi import FastAPI
from fastapi.responses import JSONResponse
from openai import OpenAI

app = FastAPI()
client = OpenAI()


@app.get("/answer")
def answer(prompt: str):
    response = client.responses.create(model="gpt-5-mini", input=prompt)
    return JSONResponse({"output": response.output_text})
