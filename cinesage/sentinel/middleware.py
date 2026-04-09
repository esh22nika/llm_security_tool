"""
SentinelLayer — Middleware Pipeline Wrapper (CineSage embedded copy)
"""
import time, uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Union

from sentinel.detector_prompt import scan_prompt, PromptScanResult
from sentinel.detector_dataset import scan_dataset_record, DatasetScanResult
from sentinel.detector_supplychain import verify_model_provenance, SupplyChainResult
from sentinel.policy_engine import PolicyEngine, PolicyConfig, PolicyDecision
from sentinel.logger import sentinel_logger as log


@dataclass
class Finding:
    detector: str
    severity: str
    threat_type: str
    description: str
    blocked: bool


@dataclass
class PipelineResult:
    request_id: str
    safe_prompt: str
    safe_context: str
    blocked: bool
    block_reason: Optional[str]
    findings: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    confidence_score: float = 0.0
    latency_ms: float = 0.0
    prompt_scan: Optional[PromptScanResult] = None
    dataset_scan: Optional[DatasetScanResult] = None
    supply_chain: Optional[SupplyChainResult] = None


def secure_llm_pipeline(
    prompt: str,
    dataset_chunk: Union[dict, str, None] = None,
    model_name: str = "unknown/model",
    model_card: Optional[str] = None,
    has_hash_signature: bool = False,
    is_deprecated: bool = False,
    lora_adapter_name: Optional[str] = None,
    use_semantic: bool = False,
    policy_config: Optional[PolicyConfig] = None,
) -> PipelineResult:
    request_id = str(uuid.uuid4())[:8]
    t_start = time.perf_counter()
    policy = PolicyEngine(config=policy_config or PolicyConfig())
    findings: list[Finding] = []

    log.info("PIPELINE", f"[{request_id}] Scan started", {"model": model_name, "prompt_len": len(prompt)})

    # STEP 1: Prompt Injection Scan
    prompt_result = scan_prompt(prompt, is_indirect=False, use_semantic=use_semantic)
    log.info("PROMPT_SCAN", f"[{request_id}] severity={prompt_result.severity}")

    if prompt_result.severity not in ("NONE", "LOW"):
        log_fn = log.block if prompt_result.blocked else log.warn
        log_fn("PROMPT_SCAN", f"[{request_id}] {prompt_result.explanation}", {
            "threat_type": prompt_result.threat_type, "risk_score": prompt_result.risk_score,
        })
        findings.append(Finding(
            detector="PROMPT", severity=prompt_result.severity,
            threat_type=prompt_result.threat_type, description=prompt_result.explanation,
            blocked=prompt_result.blocked,
        ))

    # STEP 2: Dataset Poisoning Scan
    dataset_result: Optional[DatasetScanResult] = None
    if dataset_chunk is not None:
        record = {"text": dataset_chunk} if isinstance(dataset_chunk, str) else dataset_chunk
        dataset_result = scan_dataset_record(record)
        log.info("DATASET_SCAN", f"[{request_id}] anomaly={dataset_result.anomaly_score:.2f} action={dataset_result.mitigation_action}")
        if dataset_result.poisoned_record_detected:
            log.block("DATASET_SCAN", f"[{request_id}] Poisoning detected", {
                "anomaly_score": dataset_result.anomaly_score, "details": dataset_result.details[:3],
            })
            findings.append(Finding(
                detector="DATASET",
                severity="CRITICAL" if dataset_result.anomaly_score >= 0.8 else "HIGH",
                threat_type="DATA_POISONING",
                description=f"Anomaly {dataset_result.anomaly_score:.2f}: " + "; ".join(dataset_result.details[:3]),
                blocked=True,
            ))

    # STEP 3: Supply Chain Verification
    sc_result = verify_model_provenance(
        model_name=model_name, model_card=model_card,
        has_hash_signature=has_hash_signature, is_deprecated=is_deprecated,
        lora_adapter_name=lora_adapter_name,
    )
    log.info("SUPPLY_CHAIN", f"[{request_id}] status={sc_result.provenance_status} score={sc_result.integrity_score:.2f}")

    if sc_result.provenance_status != "TRUSTED":
        log_fn = log.block if sc_result.provenance_status == "UNTRUSTED" else log.warn
        log_fn("SUPPLY_CHAIN", f"[{request_id}] Supply chain issue", {
            "status": sc_result.provenance_status, "flags": sc_result.flags[:3],
        })
        findings.append(Finding(
            detector="SUPPLY_CHAIN",
            severity="CRITICAL" if sc_result.provenance_status == "UNTRUSTED" else "HIGH",
            threat_type="SUPPLY_CHAIN_ATTACK",
            description=f"Provenance={sc_result.provenance_status}, integrity={sc_result.integrity_score:.2f}: " + "; ".join(sc_result.flags[:3]),
            blocked=sc_result.provenance_status == "UNTRUSTED",
        ))

    # STEP 4: Policy Evaluation
    policy_decision: PolicyDecision = policy.evaluate(prompt_result, dataset_result, sc_result)

    # STEP 5: Sanitization
    safe_prompt = policy.sanitize(prompt) if not policy_decision.blocked else ""
    safe_context = ""
    if dataset_chunk is not None:
        raw_context = (dataset_chunk.get("text", dataset_chunk.get("content", ""))
                       if isinstance(dataset_chunk, dict) else dataset_chunk)
        safe_context = (
            policy.sanitize(raw_context)
            if not policy_decision.blocked and (dataset_result is None or not dataset_result.poisoned_record_detected)
            else ""
        )

    t_end = time.perf_counter()
    latency_ms = round((t_end - t_start) * 1000, 2)
    confidence = policy.compute_confidence(prompt_result, dataset_result, sc_result)

    if policy_decision.blocked:
        log.block("PIPELINE", f"[{request_id}] BLOCKED violations={len(policy_decision.violations)} latency={latency_ms}ms")
    else:
        log.passthrough("PIPELINE", f"[{request_id}] ALLOWED confidence={confidence:.2f} latency={latency_ms}ms")

    return PipelineResult(
        request_id=request_id, safe_prompt=safe_prompt, safe_context=safe_context,
        blocked=policy_decision.blocked, block_reason=policy_decision.reason if policy_decision.blocked else None,
        findings=findings, warnings=policy_decision.warnings, confidence_score=confidence,
        latency_ms=latency_ms, prompt_scan=prompt_result, dataset_scan=dataset_result, supply_chain=sc_result,
    )
