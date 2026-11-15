"""werkzeug.datastructures stand-in: `FileStorage.save` is the upload class's dangerous call;
the harness replaces it with a recorder (recorders name `werkzeug.datastructures:FileStorage.save`)."""
from __future__ import annotations


class FileStorage:
    def __init__(self, stream=None, filename="", name=None, *a, **k):
        self.filename = filename
        self.name = name
        self.stream = stream

    def save(self, dst, *a, **k):          # recorder replaces this for the upload class
        return None

    def read(self, *a, **k):
        return b""
