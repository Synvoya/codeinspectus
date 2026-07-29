from fastapi import APIRouter
from openai import OpenAI

router = APIRouter()


@router.post("/answer")
def answer(request: AnswerRequest):
    client = OpenAI()
    return client.responses.create(
        model=request.model,
        instructions="Answer using only the supplied support article.",
        input=request.question,
        tools=[],
    )
