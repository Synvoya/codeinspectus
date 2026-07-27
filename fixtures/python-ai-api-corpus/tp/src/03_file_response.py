from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI()


@app.get("/download/{file_path:path}")
def download(file_path: str):
    selected = file_path
    return FileResponse(selected)
