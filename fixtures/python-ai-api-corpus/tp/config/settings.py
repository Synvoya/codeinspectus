import os

SECRET_KEY = os.getenv(
    "DJANGO_SECRET_KEY",
    "CI_PYTHON_REDACTION_SENTINEL-signing-secret-value",
)
