from langchain_community.vectorstores import FAISS


def build_index(documents, embeddings):
    return FAISS.from_documents(documents, embeddings)
