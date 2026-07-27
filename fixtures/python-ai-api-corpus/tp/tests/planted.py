from flask import redirect, request


def excluded_test_route():
    return redirect(request.args.get("next"))
