import json


def load_cfg(raw):
    return json.loads(raw)


def read_all(fh):
    return fh.read()
