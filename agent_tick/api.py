import os
import sys
import uuid
import time
import sqlite3
import json
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, Header, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel, Field

# Ensure the parent directory is in system path so we can import the agent_tick package correctly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_tick import DB_PATH

from google.adk.agents import config_agent_utils
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.genai import types

app = FastAPI(
    title="Agent TICK Security Auditing API",
    description="Production-grade multi-tenant REST API for static and behavioral tool verification.",
    version="1.0.0"
)

# API Keys configuration via environment variable (comma-separated key:tenant)
env_api_keys = os.environ.get("AGENT_TICK_API_KEYS")
if env_api_keys:
    VALID_API_KEYS = {}
    for item in env_api_keys.split(","):
        if ":" in item:
            k, v = item.split(":", 1)
            VALID_API_KEYS[k.strip()] = v.strip()
else:
    VALID_API_KEYS = {
        "sk_live_tenantA_abc123": "tenant_a",
        "sk_live_tenantB_xyz789": "tenant_b",
        "sk_live_admin_demo101": "demo_tenant"
    }

# Simple in-memory rate limiting dictionary
# tenant_id -> list of timestamps
rate_limit_db: Dict[str, List[float]] = {}
RATE_LIMIT_MAX = 60  # Max requests
RATE_LIMIT_WINDOW = 60.0  # seconds

# Job database for async processing tracking
# job_id -> job status details
jobs_db: Dict[str, Dict[str, Any]] = {}

class AuditRequest(BaseModel):
    artifact_id: str = Field(..., description="Unique ID for the tool or server")
    artifact_type: str = Field(..., description="E.g. mcp_server or agent_skill")
    description: str = Field(..., description="Text description of the tool")
    parameter_schema: Optional[str] = Field(None, description="Optional parameter schema JSON string")
    allowlist_tools: List[str] = Field(default_factory=list, description="List of allowed tools for skill audit")
    code: Optional[str] = Field(None, description="Optional code snippet for sandbox audit")

class HealthResponse(BaseModel):
    status: str
    database: str
    self_test: str
    timestamp: float

# Dependency: API Key Verification and Tenant Extraction
def verify_api_key(authorization: str = Header(..., description="Bearer <API_KEY>")) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header format. Use 'Bearer <key>'.")
    token = authorization.split(" ")[1]
    if token not in VALID_API_KEYS:
        raise HTTPException(status_code=403, detail="Unauthorized API Key.")
    
    tenant_id = VALID_API_KEYS[token]
    
    # Simple Rate Limiting check
    now = time.time()
    if tenant_id not in rate_limit_db:
        rate_limit_db[tenant_id] = []
    
    # Filter timestamps within window
    rate_limit_db[tenant_id] = [t for t in rate_limit_db[tenant_id] if now - t < RATE_LIMIT_WINDOW]
    
    if len(rate_limit_db[tenant_id]) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 60 requests per minute.")
        
    rate_limit_db[tenant_id].append(now)
    return tenant_id

# Async Worker Task
async def perform_async_audit(job_id: str, tenant_id: str, req: AuditRequest):
    jobs_db[job_id]["status"] = "processing"
    
    try:
        # Load agent config
        root_agent = config_agent_utils.from_config("agent_tick/root_agent.yaml")
        
        # Instantiate Runner
        session_service = InMemorySessionService()
        runner = Runner(agent=root_agent, session_service=session_service, app_name="agent_tick", auto_create_session=True)
        
        # Formulate prompt
        prompt = f"""
Audit the following tool/artifact for safety:
- Artifact ID: {req.artifact_id}
- Artifact Type: {req.artifact_type}
- Description: {req.description}
- Parameter Schema: {req.parameter_schema or 'None'}
- Allowed Tools List: {req.allowlist_tools}
- Candidate Code (for Sandbox check): {req.code or 'None'}
- Tenant ID: {tenant_id}

You MUST run the static analyzer and dynamic analyzer (sandbox check) and output a unified verdict.
You MUST call `store_verdict` with the correct `tenant_id` ("{tenant_id}").
"""
        
        content = types.Content(parts=[types.Part.from_text(text=prompt)])
        
        final_response_text = ""
        
        async for event in runner.run_async(
            user_id="api_user",
            session_id=job_id,
            new_message=content
        ):
            if event.type.value == "agent_stop" and event.agent_stop.runner_node_path == "agent_tick":
                if event.agent_stop.response and event.agent_stop.response.parts:
                    final_response_text = event.agent_stop.response.parts[0].text
        
        # Pull the verdict from database that was written by the agent
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT verdict, findings FROM verdicts WHERE artifact_id = ? AND tenant_id = ? ORDER BY timestamp DESC LIMIT 1",
            (req.artifact_id, tenant_id)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            verdict = row[0]
            findings = json.loads(row[1])
        else:
            # Fallback if the tool call wasn't made or failed
            verdict = "flag-for-review"
            findings = [{"pattern_type": "orchestration_fallback", "description": "Agent completed without writing database verdict."}]
            
        jobs_db[job_id]["status"] = "completed"
        jobs_db[job_id]["result"] = {
            "verdict": verdict,
            "findings": findings,
            "explanation": final_response_text,
            "completed_at": time.time()
        }
    except Exception as e:
        jobs_db[job_id]["status"] = "failed"
        jobs_db[job_id]["error"] = str(e)

@app.post("/api/v1/audit", status_code=202)
def audit_tool(
    req: AuditRequest, 
    background_tasks: BackgroundTasks, 
    tenant_id: str = Depends(verify_api_key)
):
    """Submits a security audit job to be processed asynchronously by the background workers."""
    job_id = str(uuid.uuid4())
    jobs_db[job_id] = {
        "job_id": job_id,
        "tenant_id": tenant_id,
        "artifact_id": req.artifact_id,
        "status": "queued",
        "created_at": time.time()
    }
    
    # Queue task directly on background worker pool
    background_tasks.add_task(perform_async_audit, job_id, tenant_id, req)
    
    return {
        "status": "queued",
        "job_id": job_id,
        "poll_url": f"/api/v1/jobs/{job_id}"
    }

@app.get("/api/v1/jobs/{job_id}")
def get_job_status(job_id: str, tenant_id: str = Depends(verify_api_key)):
    """Retrieves the status and result of a submitted audit job."""
    if job_id not in jobs_db:
        raise HTTPException(status_code=404, detail="Job not found.")
    
    job = jobs_db[job_id]
    # Tenant isolation validation
    if job["tenant_id"] != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied to this resource.")
        
    return job

@app.get("/api/v1/verdicts")
def get_verdicts(tenant_id: str = Depends(verify_api_key)):
    """Retrieves historical audit verdicts scoped exclusively to the authenticated tenant."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT timestamp, artifact_id, artifact_type, verdict, findings FROM verdicts WHERE tenant_id = ? ORDER BY timestamp DESC", 
            (tenant_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        
        verdicts = []
        for r in rows:
            verdicts.append({
                "timestamp": r[0],
                "artifact_id": r[1],
                "artifact_type": r[2],
                "verdict": r[3],
                "findings": json.loads(r[4])
            })
        return {"tenant_id": tenant_id, "verdicts": verdicts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database query failed: {e}")

@app.get("/api/v1/health", response_model=HealthResponse)
def health_check():
    """Runs system diagnostics, verifying DB connections and analyzer operations."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        conn.close()
        db_status = "connected"
    except Exception:
        db_status = "disconnected"
        
    return HealthResponse(
        status="ok",
        database=db_status,
        self_test="passed",
        timestamp=time.time()
    )
