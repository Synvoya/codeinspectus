from flask import Flask, redirect, url_for

app = Flask(__name__)


@app.get("/continue")
def continue_login():
    return redirect(url_for("index"))
