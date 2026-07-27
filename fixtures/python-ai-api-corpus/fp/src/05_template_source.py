from flask import Flask, render_template, request

app = Flask(__name__)


@app.post("/preview")
def preview():
    untrusted_value = request.form["template"]
    return render_template("preview.html", content=untrusted_value)
