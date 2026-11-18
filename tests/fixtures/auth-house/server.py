from app import app


def _require_controls():
    pass


@app.post("/api/update", status_code=202)
def update():
    _require_controls()
    return {}


@app.post("/api/restart", status_code=202)
def restart():
    _require_controls()
    return {}


@app.post("/api/stop", status_code=202)
def stop():
    _require_controls()
    return {}


@app.post("/api/refresh", status_code=202)
def refresh():
    _require_controls()
    return {}


@app.post("/api/sync")
def sync():
    _require_controls()
    return {}


@app.post("/api/export-jobs", status_code=202)
def start_export_job():
    # mutating handler that forgot the authz check every sibling runs
    return {"status": "running"}
