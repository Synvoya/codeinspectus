from fastapi import FastAPI
from langchain_community.document_loaders import WebBaseLoader


app = FastAPI()


@app.get("/profiles/{name}")
def profile(name: str, request: IngestRequest):
    WebBaseLoader("https://docs.example/security").load()
    WebBaseLoader("https://api.example/users/" + name).load()
    return WebBaseLoader(request.url)
