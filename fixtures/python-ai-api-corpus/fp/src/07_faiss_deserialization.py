from langchain_community.vectorstores import FAISS
from project.vectorstores import FAISS as ProjectFaiss


def load_indexes(embeddings, trusted, options):
    FAISS.load_local("default", embeddings)
    FAISS.load_local("disabled", embeddings, allow_dangerous_deserialization=False)
    FAISS.load_local("dynamic", embeddings, allow_dangerous_deserialization=trusted)
    FAISS.load_local(
        "spread",
        embeddings,
        allow_dangerous_deserialization=True,
        **options,
    )
    ProjectFaiss.load_local(
        "lookalike",
        embeddings,
        allow_dangerous_deserialization=True,
    )
