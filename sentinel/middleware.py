"""
SentinelLayer — Middleware Pipeline Wrapper
============================================
Orchestrates the full security scanning pipeline:

  user prompt
      ↓
  [1] Prompt Injection Scan      (detector_prompt)
      ↓
  [2] Dataset Poisoning Scan     (detector_dataset)
      ↓
  [3] Supply Chain Verification  (detector_supplychain)
      ↓
  [4] Policy Evaluation          (policy_engine)
      ↓
  [5] Sanitization               (policy_engine.sanitize)
      ↓
  [6] Logging                    (logger)
      ↓
  [7] Forward or Block           → safe_prompt + safe_context returned

Public API:
  secure_llm_pipeline(
      prompt: str,
      dataset_chunk: dict | str,
      model_name: str,
      **model_kwargs
  ) -> PipelineResult
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Union

from sentinel.detector_prompt import scan_prompt, PromptScanResult
from sentinel.detector_dataset import scan_dataset_record, scan_dataset_batch, DatasetScanResult
from sentinel.detector_supplychain import verify_model_provenance, SupplyChainResult
from sentinel.policy_engine import PolicyEngine, PolicyConfig, PolicyDecision
from sentinel.logger import sentinel_logger as log


# ─────────────────────────────────────────────────────────────────────────────
# RESULT DATACLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single detected security finding from any detector."""
    detector: str        # "PROMPT" | "DATASET" | "SUPPLY_CHAIN"
    severity: str        # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    threat_type: str
    description: str
    blocked: bool


@dataclass
class PipelineResult:
    """
    The output of secure_llm_pipeline().
    Consumers should check `blocked` before forwarding `safe_prompt` to an LLM.
    """
    request_id: str
    safe_prompt: str                         # sanitized prompt (may be empty if blocked)
    safe_context: str                        # sanitized dataset context
    safe_records: list[dict] = field(default_factory=list)
    blocked: bool
    block_reason: Optional[str]
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str]     = field(default_factory=list)
    confidence_score: float = 0.0           # 0.0 – 1.0 (higher = safer)
    latency_ms: float = 0.0
    # Raw detector results (included for observability)
    prompt_scan: Optional[PromptScanResult]      = None
    dataset_scan: Optional[DatasetScanResult]    = None
    supply_chain: Optional[SupplyChainResult]    = None


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def secure_llm_pipeline(
    prompt: str,
    dataset_chunk: Union[dict, str, list[dict], list[str], None] = None,
    model_name: str = "unknown/model",
    model_card: Optional[str] = None,
    has_hash_signature: bool = False,
    is_deprecated: bool = False,
    lora_adapter_name: Optional[str] = None,
    use_semantic: bool = False,    # set True when sentence-transformers is installed
    policy_config: Optional[PolicyConfig] = None,
) -> PipelineResult:
    """
    Run the full SentinelLayer security pipeline on a request before it
    reaches the LLM.

    Args:
        prompt:            Raw user-supplied prompt text.
        dataset_chunk:     A single RAG-retrieved record (dict), plain text chunk,
                           or a list of retrieved records/chunks.
        model_name:        HuggingFace model repo ID to validate.
        model_card:        Optional model card content for provenance checks.
        has_hash_signature: Whether the model has a published hash.
        is_deprecated:     Whether the model is flagged deprecated.
        lora_adapter_name: Optional LoRA adapter repo ID to validate.
        use_semantic:      Enable semantic similarity scoring (needs sentence-transformers).
        policy_config:     Override default PolicyConfig.

    Returns:
        PipelineResult — consumers must check `.blocked` before using `.safe_prompt`.
    """
    request_id = str(uuid.uuid4())[:8]
    t_start = time.perf_counter()
    policy = PolicyEngine(config=policy_config or PolicyConfig())
    findings: list[Finding] = []

    log.info("PIPELINE", f"[{request_id}] Scan started", {
        "model": model_name, "prompt_len": len(prompt)
    })

    # ── STEP 1: Prompt Injection Scan ─────────────────────────────────────────
    prompt_result = scan_prompt(prompt, is_indirect=False, use_semantic=use_semantic)
    log.info("PROMPT_SCAN", f"[{request_id}] Prompt scan complete | severity={prompt_result.severity}")

    if prompt_result.severity not in ("NONE", "LOW"):
        log_fn = log.block if prompt_result.blocked else log.warn
        log_fn("PROMPT_SCAN", f"[{request_id}] {prompt_result.explanation}", {
            "threat_type": prompt_result.threat_type,
            "risk_score": prompt_result.risk_score,
        })
        findings.append(Finding(
            detector="PROMPT",
            severity=prompt_result.severity,
            threat_type=prompt_result.threat_type,
            description=prompt_result.explanation,
            blocked=prompt_result.blocked,
        ))

    # ── STEP 2: Dataset/RAG Chunk Poisoning Scan ──────────────────────────────
    dataset_result: Optional[DatasetScanResult] = None
    if dataset_chunk is not None:
        # Normalize to dict
        if isinstance(dataset_chunk, str):
            record = {"text": dataset_chunk}
        else:
            record = dataset_chunk

        dataset_result = scan_dataset_record(record)
        log.info("DATASET_SCAN", f"[{request_id}] Dataset scan complete | "
                 f"anomaly_score={dataset_result.anomaly_score:.2f} | "
                 f"action={dataset_result.mitigation_action}")

        if dataset_result.poisoned_record_detected:
            log.block("DATASET_SCAN", f"[{request_id}] Dataset poisoning detected — "
                      f"action={dataset_result.mitigation_action}", {
                          "anomaly_score": dataset_result.anomaly_score,
                          "details": dataset_result.details[:3],
                      })
            findings.append(Finding(
                detector="DATASET",
                severity="CRITICAL" if dataset_result.anomaly_score >= 0.8 else "HIGH",
                threat_type="DATA_POISONING",
                description=f"Anomaly score {dataset_result.anomaly_score:.2f}: "
                            + "; ".join(dataset_result.details[:3]),
                blocked=True,
            ))

    # ── STEP 3: Supply Chain Verification ────────────────────────────────────
    sc_result = verify_model_provenance(
        model_name=model_name,
        model_card=model_card,
        has_hash_signature=has_hash_signature,
        is_deprecated=is_deprecated,
        lora_adapter_name=lora_adapter_name,
    )
    log.info("SUPPLY_CHAIN", f"[{request_id}] Provenance check | "
             f"status={sc_result.provenance_status} | score={sc_result.integrity_score:.2f}")

    if sc_result.provenance_status != "TRUSTED":
        log_fn = log.block if sc_result.provenance_status == "UNTRUSTED" else log.warn
        log_fn("SUPPLY_CHAIN", f"[{request_id}] Supply chain issue detected", {
            "status": sc_result.provenance_status,
            "integrity_score": sc_result.integrity_score,
            "flags": sc_result.flags[:3],
        })
        findings.append(Finding(
            detector="SUPPLY_CHAIN",
            severity="CRITICAL" if sc_result.provenance_status == "UNTRUSTED" else "HIGH",
            threat_type="SUPPLY_CHAIN_ATTACK",
            description=f"Provenance={sc_result.provenance_status}, "
                        f"integrity={sc_result.integrity_score:.2f}: "
                        + "; ".join(sc_result.flags[:3]),
            blocked=sc_result.provenance_status == "UNTRUSTED",
        ))

    # ── STEP 4: Policy Evaluation ─────────────────────────────────────────────
    policy_decision: PolicyDecision = policy.evaluate(prompt_result, dataset_result, sc_result)

    # ── STEP 5: Sanitization ──────────────────────────────────────────────────
    safe_prompt  = policy.sanitize(prompt) if not policy_decision.blocked else ""
    safe_context = ""
    if dataset_chunk is not None:
        raw_context = (
            dataset_chunk.get("text", dataset_chunk.get("content", ""))
            if isinstance(dataset_chunk, dict) else dataset_chunk
        )
        safe_context = (
            policy.sanitize(raw_context)
            if not policy_decision.blocked and (dataset_result is None or not dataset_result.poisoned_record_detected)
            else ""
        )

    # ── STEP 6: Logging result ────────────────────────────────────────────────
    t_end = time.perf_counter()
    latency_ms = round((t_end - t_start) * 1000, 2)

    confidence = policy.compute_confidence(prompt_result, dataset_result, sc_result)

    if policy_decision.blocked:
        log.block("PIPELINE", f"[{request_id}] Request BLOCKED | "
                  f"violations={len(policy_decision.violations)} | latency={latency_ms}ms", {
                      "blocked_by": policy_decision.violations[:2],
                  })
    else:
        log.passthrough("PIPELINE", f"[{request_id}] Safe request forwarded to LLM | "
                        f"confidence={confidence:.2f} | latency={latency_ms}ms")

    # ── STEP 7: Return result ─────────────────────────────────────────────────
    return PipelineResult(
        request_id=request_id,
        safe_prompt=safe_prompt,
        safe_context=safe_context,
        blocked=policy_decision.blocked,
        block_reason=policy_decision.reason if policy_decision.blocked else None,
        findings=findings,
        warnings=policy_decision.warnings,
        confidence_score=confidence,
        latency_ms=latency_ms,
        prompt_scan=prompt_result,
        dataset_scan=dataset_result,
        supply_chain=sc_result,
    )
