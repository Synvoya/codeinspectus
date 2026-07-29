from fastapi import FastAPI
from langchain_community.document_loaders import WebBaseLoader


app = FastAPI()


@app.post("/ingest")
def ingest(request: IngestRequest):
    loader = WebBaseLoader(request.url)
    return loader.load()
