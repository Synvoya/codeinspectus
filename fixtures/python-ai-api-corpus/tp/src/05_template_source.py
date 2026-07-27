from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.post("/preview")
def preview():
    source = request.form["template"]
    return render_template_string(source)
