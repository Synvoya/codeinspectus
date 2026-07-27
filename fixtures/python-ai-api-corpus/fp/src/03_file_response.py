from pathlib import Path

from flask import Flask, send_from_directory, request

app = Flask(__name__)
DOWNLOAD_ROOT = Path("/srv/downloads")


@app.get("/download")
def download():
    requested = request.args.get("name")
    return send_from_directory(DOWNLOAD_ROOT, requested)
