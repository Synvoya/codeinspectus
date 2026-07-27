import os
import secrets

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
SECRET_KEY_FALLBACKS = [secrets.token_urlsafe(64)]
