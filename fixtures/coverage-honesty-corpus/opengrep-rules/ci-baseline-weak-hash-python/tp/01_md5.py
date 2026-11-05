import hashlib


def digest(data):
    return hashlib.md5(data).hexdigest()
