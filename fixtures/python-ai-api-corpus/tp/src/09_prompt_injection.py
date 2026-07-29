from fastapi import APIRouter
from openai import OpenAI

router = APIRouter()


@router.post("/research")
def research(request: ResearchRequest):
    client = OpenAI()
    return client.responses.create(
        model="gpt-4.1",
        instructions=request.instructions,
        input=request.topic,
        tools=[{"type": "web_search_preview"}],
    )
