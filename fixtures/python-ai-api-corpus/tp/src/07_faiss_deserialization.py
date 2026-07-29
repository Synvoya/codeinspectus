from langchain_community.vectorstores import FAISS


def load_index(embeddings):
    return FAISS.load_local(
        "vector_store_index",
        embeddings,
        allow_dangerous_deserialization=True,
    )
