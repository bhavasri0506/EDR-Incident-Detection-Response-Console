import os
import sqlite3
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="EDR Threat Intel & Telemetry API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.path.join(os.path.dirname(__file__), "edr_telemetry.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            host TEXT,
            pid INTEGER,
            process_name TEXT,
            cmdline TEXT,
            sha256 TEXT,
            severity TEXT,
            status TEXT,
            attack_name TEXT,
            mitre_id TEXT,
            description TEXT,
            resolution TEXT
        )
    """)
    conn.commit()

    # Auto-migration: Pazhaya database irundhaalum columns-a automatic-ah add pannidum
    cursor.execute("PRAGMA table_info(telemetry)")
    existing_cols = [row[1] for row in cursor.fetchall()]
    
    needed_cols = {
        "attack_name": "TEXT DEFAULT 'Normal Process'",
        "mitre_id": "TEXT DEFAULT '-'",
        "description": "TEXT DEFAULT 'Standard system operation.'",
        "resolution": "TEXT DEFAULT 'No action required.'"
    }
    
    for col, col_type in needed_cols.items():
        if col not in existing_cols:
            cursor.execute(f"ALTER TABLE telemetry ADD COLUMN {col} {col_type}")
            conn.commit()

    conn.close()

init_db()

class TelemetryPayload(BaseModel):
    timestamp: str
    host: str
    pid: int
    process_name: str
    cmdline: str
    sha256: Optional[str] = "N/A"
    severity: str
    status: str
    attack_name: Optional[str] = "Normal Process"
    mitre_id: Optional[str] = "-"
    description: Optional[str] = "Standard system operation."
    resolution: Optional[str] = "No action required."

@app.post("/api/telemetry")
def receive_telemetry(payload: TelemetryPayload):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO telemetry 
            (timestamp, host, pid, process_name, cmdline, sha256, severity, status, attack_name, mitre_id, description, resolution)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            payload.timestamp, payload.host, payload.pid, payload.process_name,
            payload.cmdline, payload.sha256, payload.severity, payload.status,
            payload.attack_name, payload.mitre_id, payload.description, payload.resolution
        ))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Telemetry logged"}
    except Exception as e:
        print(f"[DB Error] {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts")
def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, host, pid, process_name, cmdline, sha256, severity, status, attack_name, mitre_id, description, resolution 
        FROM telemetry ORDER BY id DESC LIMIT 100
    """)
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        result.append({
            "timestamp": r[0],
            "host": r[1],
            "pid": r[2],
            "process_name": r[3],
            "cmdline": r[4],
            "sha256": r[5] if r[5] else "N/A",
            "severity": r[6],
            "status": r[7],
            "attack_name": r[8] if r[8] else "Normal Process",
            "mitre_id": r[9] if r[9] else "-",
            "description": r[10] if r[10] else "Standard system operation.",
            "resolution": r[11] if r[11] else "No action required."
        })
    return result

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=5000, reload=False)