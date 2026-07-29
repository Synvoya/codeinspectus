from langchain_community.document_loaders import WebBaseLoader


TRUSTED_SOURCES = {
    "security": "https://docs.example/security",
    "api": "https://docs.example/api",
}


def ingest(source_name: str):
    loader = WebBaseLoader(TRUSTED_SOURCES[source_name])
    return loader.load()
