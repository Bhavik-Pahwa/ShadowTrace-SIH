from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr


class AlertItem(BaseModel):
    tx_id: str
    threat_score: int
    timestamp: str
    primary_anomaly: str
    risk_level: str


class AlertsResponse(BaseModel):
    status: str = "success"
    total_count: int
    alerts: list[AlertItem]


class IngestResponse(BaseModel):
    status: str = "success"
    message: str = "Dataset ingested successfully."
    job_id: str
    rows_processed: int


class DossierRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tx_id: StrictStr
    investigator_id: StrictStr
    include_xai_visuals: StrictBool
    include_network_metadata: StrictBool


class DossierResponse(BaseModel):
    status: str = "success"
    message: str = "Dossier generated successfully."
    file_path: str
    download_url: str


class ErrorResponse(BaseModel):
    status: str = "error"
    code: int
    message: str
    details: str


class GraphElements(BaseModel):
    nodes: list[dict]
    edges: list[dict]


class GraphResponse(BaseModel):
    tx_id: str
    elements: GraphElements


class EvidenceFeature(BaseModel):
    feature: str
    value: str
    contribution_percentage: float = Field(ge=0)


class EvidenceResponse(BaseModel):
    tx_id: str
    overall_threat_score: int
    xai_breakdown: list[EvidenceFeature]
    chain_of_custody_hash: str


class FeedbackRequest(BaseModel):
    tx_id: StrictStr
    ai_score: float
    human_label: int
    reviewed_by: StrictStr = "investigator"
