import json
import sqlite3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
import uvicorn

app = FastAPI(title="ShadowTrace API")

# Initialize SQLite database for the Active Learning loop
conn = sqlite3.connect("feedback.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tx_id TEXT,
        ai_score REAL,
        human_label INTEGER,
        reviewed_by TEXT,
        timestamp TEXT
    )
""")
conn.commit()

# Define the expected JSON payload from the frontend
class FeedbackPayload(BaseModel):
    tx_id: str
    ai_score: float
    human_label: int  # 0 for False Positive (Licit), 1 for True Positive (Illicit)
    reviewed_by: str = "investigator"

@app.get("/api/investigate/{tx_id}")
async def get_investigation_data(tx_id: str):
    try:
        # Serve the pre-computed GNNExplainer weights for the SIH prototype
        with open("outputs/xai_sample.json", "r") as f:
            xai_data = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="XAI sample not found.")

    return {
        "tx_id": tx_id,
        "risk_level": "HIGH",
        "risk_score": 0.91,
        "prediction": "suspicious",
        "xai_explanation": {
            "target_node": xai_data.get("target_node"),
            "feature_weights": xai_data.get("feature_weights", [])[:5] 
        }
    }

@app.post("/api/feedback")
async def submit_investigator_feedback(payload: FeedbackPayload):
    timestamp = datetime.now().isoformat()
    
    cursor.execute("""
        INSERT INTO feedback (tx_id, ai_score, human_label, reviewed_by, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (payload.tx_id, payload.ai_score, payload.human_label, payload.reviewed_by, timestamp))
    conn.commit()

    return {
        "status": "success",
        "message": f"Feedback logged. Node {payload.tx_id} queued for next training batch.",
        "recorded_timestamp": timestamp
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)