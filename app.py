"""
SentinelLayer — FastAPI Demo Server
=====================================
Exposes:

  POST /chat
    Intercepts LLM requests. Runs the full security pipeline before forwarding.

  POST /sentinel/simulate
    Runs all 5 attack simulation scenarios and returns detection outputs.

  GET  /sentinel/logs
    Returns recent security event logs (filterable by severity level).

  GET  /sentinel/health
    Health check endpoint with system status.

  GET  /docs
    Auto-generated Swagger UI for interactive testing.

Run with:
  uvicorn app:app --reload --port 8000
"""

from __future__ import annotations

import contextlib
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from sentinel.middleware import secure_llm_pipeline, PipelineResult
from sentinel.logger import sentinel_logger as log
from simulator import run_all_scenarios, _result_to_dict


# ─────────────────────────────────────────────────────────────────────────────
# APP SETUP
# ─────────────────────────────────────────────────────────────────────────────

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("APP", "SentinelLayer FastAPI server started")
    yield
    log.info("APP", "SentinelLayer FastAPI server shutting down")


app = FastAPI(
    title="SentinelLayer — LLM Security Middleware",
    description=(
        "OWASP LLM Top 10 (2025) protection middleware for LLM applications.\n\n"
        "Protects against:\n"
        "- **LLM01** Prompt Injection\n"
        "- **LLM03** Supply Chain Attacks\n"
        "- **LLM04** Data & Model Poisoning\n\n"
        "Use `POST /chat` as a drop-in security layer before your LLM endpoint."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Allow all origins for demo purposes (tighten in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST / RESPONSE SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=8192,
        description="Raw user prompt to be scanned and forwarded to the LLM",
        examples=["What is the capital of France?"],
    )
    dataset_chunk: Optional[dict] = Field(
        None,
        description="Optional RAG-retrieved dataset record to scan for poisoning",
    )
    model_name: str = Field(
        "meta-llama/Llama-2-7b-hf",
        description="HuggingFace model repo ID to verify supply chain provenance",
    )
    model_card: Optional[str] = Field(
        None,
        description="Model card README content (leave empty to simulate missing card)",
    )
    has_hash_signature: bool = Field(
        False,
        description="Whether the model has a published cryptographic hash signature",
    )
    is_deprecated: bool = Field(False, description="Whether the model is deprecated")
    lora_adapter_name: Optional[str] = Field(
        None,
        description="Optional LoRA adapter HuggingFace repo ID to validate",
    )
    use_semantic: bool = Field(
        False,
        description="Enable semantic similarity scoring (requires sentence-transformers)",
    )


class FindingSchema(BaseModel):
    detector: str
    severity: str
    threat_type: str
    description: str
    blocked: bool


class ChatResponse(BaseModel):
    request_id: str
    safe_prompt: str
    safe_context: str
    blocked: bool
    block_reason: Optional[str]
    findings: list[FindingSchema]
    warnings: list[str]
    confidence_score: float
    latency_ms: float


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.post(
    "/chat",
    response_model=ChatResponse,
    summary="Secure Chat Endpoint",
    description=(
        "Intercepts an LLM request, runs the full SentinelLayer security pipeline, "
        "and returns a safe (sanitized) prompt if the request passes all checks. "
        "If blocked, returns the reason and findings."
    ),
    tags=["Core"],
)
async def secure_chat(body: ChatRequest):
    """
    Main security intercept middleware endpoint.

    **Flow:**
    1. Scan prompt for injection signals
    2. Scan dataset chunk for poisoning signals
    3. Verify model supply chain provenance
    4. Apply policy (block/allow/warn)
    5. Sanitize safe content
    6. Return result

    If `blocked=true`, **do not** forward the prompt to the LLM.
    """
    log.info("APP", f"POST /chat received | model={body.model_name} | "
             f"prompt_len={len(body.prompt)}")

    result: PipelineResult = secure_llm_pipeline(
        prompt=body.prompt,
        dataset_chunk=body.dataset_chunk,
        model_name=body.model_name,
        model_card=body.model_card,
        has_hash_signature=body.has_hash_signature,
        is_deprecated=body.is_deprecated,
        lora_adapter_name=body.lora_adapter_name,
        use_semantic=body.use_semantic,
    )

    return ChatResponse(
        request_id=result.request_id,
        safe_prompt=result.safe_prompt,
        safe_context=result.safe_context,
        blocked=result.blocked,
        block_reason=result.block_reason,
        findings=[
            FindingSchema(
                detector=f.detector,
                severity=f.severity,
                threat_type=f.threat_type,
                description=f.description,
                blocked=f.blocked,
            )
            for f in result.findings
        ],
        warnings=result.warnings,
        confidence_score=result.confidence_score,
        latency_ms=result.latency_ms,
    )


@app.post(
    "/sentinel/simulate",
    summary="Run Attack Simulation Suite",
    description=(
        "Executes all 5 pre-built attack scenarios and returns their detection outputs. "
        "Useful for demonstrating SentinelLayer's capabilities."
    ),
    tags=["Observability"],
)
async def simulate_attacks(use_semantic: bool = Query(False)):
    """
    Run the full SentinelLayer attack simulation suite.

    Returns detection outputs for:
    - Direct Prompt Injection
    - Indirect RAG Injection
    - Poisoned Dataset Record
    - Untrusted Supply Chain (typosquatted model)
    - Clean Safe Request (baseline)
    """
    log.info("APP", "POST /sentinel/simulate — running all 5 attack scenarios")
    results = run_all_scenarios(use_semantic=use_semantic)
    blocked_count = sum(1 for r in results if r["result"]["blocked"])
    return {
        "total_scenarios": len(results),
        "blocked": blocked_count,
        "passed": len(results) - blocked_count,
        "scenarios": results,
    }


@app.get(
    "/sentinel/logs",
    summary="Retrieve Security Logs",
    description=(
        "Returns recent security event log records from the in-memory ring buffer. "
        "Filter by minimum severity level: INFO < PASS < WARN < BLOCK < ERROR."
    ),
    tags=["Observability"],
)
async def get_logs(
    level: Optional[str] = Query(
        None,
        description="Minimum log level to return (INFO | PASS | WARN | BLOCK | ERROR)",
    ),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
):
    """
    Retrieve recent SentinelLayer security event logs.

    **Log Levels (ascending severity):**
    - `INFO`  — General pipeline events
    - `PASS`  — Safe requests forwarded to LLM
    - `WARN`  — Potential threat detected (not blocked)
    - `BLOCK` — Request blocked due to security violation
    - `ERROR` — Internal processing error
    """
    records = log.get_logs(level_filter=level, limit=limit, as_dict=True)
    return {
        "total_records": log.record_count,
        "returned": len(records),
        "level_filter": level or "ALL",
        "logs": records,
    }


@app.get(
    "/sentinel/health",
    summary="Health Check",
    tags=["System"],
)
async def health_check():
    """Returns system health status and component availability."""
    try:
        from sentence_transformers import SentenceTransformer
        semantic_available = True
    except ImportError:
        semantic_available = False

    return {
        "status": "healthy",
        "version": "1.0.0",
        "components": {
            "prompt_injection_detector": "active",
            "dataset_poisoning_detector": "active",
            "supply_chain_verifier": "active",
            "policy_engine": "active",
            "logger": "active",
            "semantic_scoring": "active" if semantic_available else "unavailable (install sentence-transformers)",
        },
        "log_buffer_size": log.record_count,
    }


@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": "SentinelLayer",
        "description": "OWASP LLM Top 10 (2025) Middleware Framework",
        "docs": "/docs",
        "health": "/sentinel/health",
        "logs": "/sentinel/logs",
        "simulate": "POST /sentinel/simulate",
    }
