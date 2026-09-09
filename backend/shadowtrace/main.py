import shutil
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import DEFAULT_HOPS, REPORTS_DIR
from .dossier import generate_dossier
from .errors import ShadowTraceError, http_exception_handler, raise_error, shadowtrace_exception_handler, unhandled_exception_handler, validation_exception_handler
from .pipeline import ShadowTracePipeline
from .schemas import AlertsResponse, DossierRequest, DossierResponse, EvidenceResponse, FeedbackRequest, GraphResponse, IngestResponse
from .team_model import TeamModelUnavailable, record_feedback, team_model_adapter

pipeline = ShadowTracePipeline()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        yield
    finally:
        pipeline.store.close()


app = FastAPI(title="ShadowTrace-XAI Backend", version="0.1.0", lifespan=lifespan)
app.add_exception_handler(ShadowTraceError, shadowtrace_exception_handler)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/ingest", response_model=IngestResponse)
async def ingest(file: UploadFile = File(...)):
    if not file.filename:
        raise_error(400, "Malformed ingest file.", "No file name was supplied.")
    suffix = Path(file.filename).suffix.lower()
    if suffix != ".csv":
        raise_error(400, "Malformed ingest file.", "Only CSV files are supported by /api/ingest.")
    job_id = "job_" + uuid4().hex[:8]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = Path(tmp.name)
    try:
        rows_processed = pipeline.ingest_file(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
    return {
        "status": "success",
        "message": "Dataset ingested successfully.",
        "job_id": job_id,
        "rows_processed": rows_processed,
    }


@app.get("/api/alerts", response_model=AlertsResponse)
async def alerts(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    total_count = pipeline.store.count_alerts()
    if total_count == 0:
        if not pipeline.store.fetch_transactions():
            raise_error(400, "Empty dataset.", "No ingested transactions are available for alert generation.")
    return {
        "status": "success",
        "total_count": total_count,
        "alerts": pipeline.store.fetch_alerts(limit=limit, offset=offset),
    }


@app.get("/api/graph/{tx_id}", response_model=GraphResponse)
async def graph(tx_id: str):
    if pipeline.store.fetch_transaction(tx_id) is None:
        raise_error(404, "Entity not found in the graph.", "No hops available for the given tx_id.")
    elements = pipeline.graph_elements(tx_id, hops=DEFAULT_HOPS)
    if not elements["nodes"]:
        raise_error(404, "Entity not found in the graph.", "No hops available for the given tx_id.")
    return {"tx_id": tx_id, "elements": elements}


@app.get("/api/evidence/{tx_id}", response_model=EvidenceResponse)
async def evidence(tx_id: str):
    item = pipeline.store.fetch_evidence(tx_id)
    if item is None:
        if pipeline.store.fetch_transaction(tx_id) is None:
            raise_error(404, "Entity not found in the graph.", "No evidence is available for the given tx_id.")
        raise_error(404, "Evidence not found.", "The transaction exists but has not been flagged as an alert.")
    total = sum(feature["contribution_percentage"] for feature in item["xai_breakdown"])
    if total != item["overall_threat_score"]:
        raise_error(500, "Invalid evidence attribution.", "XAI contribution percentages do not sum to the threat score.")
    return item


@app.get("/api/investigate/{tx_id}")
async def investigate(tx_id: str):
    try:
        prediction = team_model_adapter.predict(tx_id)
    except KeyError:
        alert = pipeline.store.fetch_alert(tx_id)
        evidence_item = pipeline.store.fetch_evidence(tx_id)
        if alert is None or evidence_item is None:
            raise_error(404, "Entity not found in the graph.", "No team-model investigation is available for the given tx_id.")
        return {
            "tx_id": tx_id,
            "risk_level": alert["risk_level"],
            "risk_score": round(alert["threat_score"] / 100, 6),
            "prediction": "suspicious",
            "xai_explanation": {
                "target_node": tx_id,
                "feature_weights": evidence_item["xai_breakdown"][:5],
            },
        }
    except TeamModelUnavailable as exc:
        raise_error(503, "Team ML model unavailable.", str(exc))
    return {
        "tx_id": prediction.tx_id,
        "risk_level": prediction.risk_level,
        "risk_score": prediction.risk_score,
        "prediction": prediction.prediction,
        "xai_explanation": prediction.xai_explanation,
    }


@app.post("/api/feedback")
async def feedback(request: FeedbackRequest):
    try:
        return record_feedback(
            tx_id=request.tx_id,
            ai_score=request.ai_score,
            human_label=request.human_label,
            reviewed_by=request.reviewed_by,
        )
    except ValueError as exc:
        raise_error(400, "Malformed feedback payload.", str(exc))


@app.post("/api/generate-dossier", response_model=DossierResponse)
async def dossier(request: DossierRequest):
    tx = pipeline.store.fetch_transaction(request.tx_id)
    if tx is None:
        raise_error(404, "Entity not found in the graph.", "No dossier can be generated for an unknown tx_id.")
    evidence_item = pipeline.store.fetch_evidence_with_subgraph(request.tx_id)
    if evidence_item is None:
        raise_error(404, "Evidence not found.", "The transaction exists but has not been flagged as an alert.")
    alert = pipeline.store.fetch_alert(request.tx_id)
    if alert is None:
        raise_error(404, "Evidence not found.", "No alert row is available for the given tx_id.")
    elements = pipeline.graph_elements(request.tx_id)
    output, _elapsed = generate_dossier(
        tx_id=request.tx_id,
        investigator_id=request.investigator_id,
        alert=alert,
        evidence=evidence_item,
        graph=elements,
        xai_graph=pipeline.explainer_subgraphs.get(request.tx_id) or evidence_item.get("xai_subgraph"),
        include_xai_visuals=request.include_xai_visuals,
        include_network_metadata=request.include_network_metadata,
    )
    return {
        "status": "success",
        "message": "Dossier generated successfully.",
        "file_path": str(output),
        "download_url": f"/api/downloads/{output.name}",
    }


def _report_file(file_name: str) -> Path:
    candidate = (REPORTS_DIR / file_name).resolve()
    reports_root = REPORTS_DIR.resolve()
    if reports_root not in candidate.parents or candidate.suffix.lower() != ".pdf":
        raise_error(404, "Report not found.", "No generated dossier is available at the requested path.")
    if not candidate.exists() or not candidate.is_file():
        raise_error(404, "Report not found.", "No generated dossier is available at the requested path.")
    return candidate


@app.get("/api/downloads/{file_name}")
async def download_report(file_name: str):
    return FileResponse(_report_file(file_name), media_type="application/pdf", filename=file_name)


@app.head("/api/downloads/{file_name}")
async def head_report(file_name: str):
    return FileResponse(_report_file(file_name), media_type="application/pdf", filename=file_name)


@app.get("/api/downloads/{file_name:path}", include_in_schema=False)
async def download_report_path(file_name: str):
    return FileResponse(_report_file(file_name), media_type="application/pdf", filename=Path(file_name).name)


@app.head("/api/downloads/{file_name:path}", include_in_schema=False)
async def head_report_path(file_name: str):
    return FileResponse(_report_file(file_name), media_type="application/pdf", filename=Path(file_name).name)
