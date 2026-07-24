"""
API gateway — thin FastAPI surface over the pipeline.

Endpoints are the integration seam for a regulator/agency console:
  POST /observations     submit candidate streams (tip-offs / collector output)
  POST /pipeline/run     detect -> attribute -> generate blocklist
  GET  /operators        current inferred operator clusters
  GET  /blocklist        latest precision blocklist
  GET  /evidence/verify  prove the audit chain is intact

Run: uvicorn aegis.api.main:app --reload
Requires fastapi + uvicorn (see requirements.txt). The core pipeline itself has
no such dependency and is exercised by demo/run_pipeline.py without a server.
"""
from __future__ import annotations

from typing import Optional

try:
    from fastapi import FastAPI
    from pydantic import BaseModel
except Exception:  # pragma: no cover - lets the repo import without fastapi
    FastAPI = None  # type: ignore
    BaseModel = object  # type: ignore

from aegis.pipeline import Pipeline
from aegis.models import StreamObservation, to_json


# Defined at module scope (not inside create_app) so the request-body type
# resolves under `from __future__ import annotations` — a function-local model
# leaves `list[Observation]` as an unresolvable forward ref and FastAPI/pydantic
# fail with "class not fully defined". Optional[str] (not `str | None`) keeps the
# Python 3.9 floor honest.
class Observation(BaseModel):
    url: str
    source: str = "api"
    event_hint: Optional[str] = None


def create_app():
    if FastAPI is None:
        raise RuntimeError("Install fastapi + uvicorn to run the API gateway.")

    app = FastAPI(title="AEGIS", version="0.1.0",
                  description="Anti-piracy Enforcement & Graph Intelligence System")
    pipeline = Pipeline.demo_instance()

    @app.post("/observations")
    def add_observations(items: list[Observation]):
        obs = [StreamObservation(url=i.url, source=i.source, event_hint=i.event_hint)
               for i in items]
        pipeline.add_observations(obs)
        return {"accepted": len(obs)}

    @app.post("/pipeline/run")
    def run():
        result = pipeline.run()
        return {"detections": len([d for d in result.detections if d.matched]),
                "blocklist_entries": len(result.blocklist),
                "operators": pipeline.graph.summarise()}

    @app.get("/operators")
    def operators():
        return pipeline.graph.summarise()

    @app.get("/blocklist")
    def blocklist():
        return {"entries": [e.__dict__ for e in pipeline.last_blocklist]}

    @app.get("/evidence/verify")
    def verify():
        return {"records": len(pipeline.evidence), "intact": pipeline.evidence.verify()}

    return app


app = create_app() if FastAPI is not None else None
