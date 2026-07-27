from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from openai import OpenAI

app = FastAPI()
client = OpenAI()


@app.get("/answer", response_class=HTMLResponse)
def answer(prompt: str):
    response = client.responses.create(model="gpt-5-mini", input=prompt)
    generated = response.output_text
    return HTMLResponse(generated)
