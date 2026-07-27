from flask import render_template_string, request


def excluded_example_route():
    return render_template_string(request.form["template"])
