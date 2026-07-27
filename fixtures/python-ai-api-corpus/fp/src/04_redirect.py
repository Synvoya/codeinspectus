from urllib.parse import urlsplit

from flask import Flask, redirect, request, url_for

app = Flask(__name__)


@app.get("/continue")
def continue_login():
    target = request.args.get("next")
    parsed = urlsplit(target)
    if not target or parsed.scheme or parsed.netloc or "\\" in target:
        target = url_for("index")
    return redirect(target)
