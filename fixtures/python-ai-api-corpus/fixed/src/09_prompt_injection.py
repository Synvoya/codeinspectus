from fastapi import APIRouter
from openai import OpenAI

router = APIRouter()


@router.post("/research")
def research(request: ResearchRequest):
    client = OpenAI()
    return client.responses.create(
        model="gpt-4.1",
        instructions="Research the user's topic without taking external actions.",
        input=request.topic,
    )
