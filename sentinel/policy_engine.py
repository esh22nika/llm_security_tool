"""
SentinelLayer — Policy Engine
==============================
Centralizes risk thresholds, block/warn rules, and prompt sanitization.

Configuration:
  • BLOCK severity levels per threat category
  • Anomaly score thresholds for dataset poisoning
  • Supply chain integrity thresholds
  • Text sanitizer to strip dangerous tokens before forwarding to LLM

Usage:
  policy = PolicyEngine()
  decision = policy.evaluate(prompt_result, dataset_result, supply_chain_result)
  safe_prompt = policy.sanitize(prompt)
"""

import re
from dataclasses import dataclass, field
from typing import Any, Optional


# ─────────────────────────────────────────────────────────────────────────────
# POLICY CONFIGURATION (tuneable)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PolicyConfig:
    # ── Prompt Injection ──────────────────────────────────────────────────────
    block_on_prompt_severity: set = field(
        default_factory=lambda: {"HIGH", "CRITICAL"}
    )
    warn_on_prompt_severity: set = field(
        default_factory=lambda: {"MEDIUM"}
    )

    # ── Dataset Poisoning ─────────────────────────────────────────────────────
    block_on_dataset_action: set = field(
        default_factory=lambda: {"FILTER", "QUARANTINE"}
    )
    dataset_anomaly_block_threshold: float = 0.55

    # ── Supply Chain ──────────────────────────────────────────────────────────
    block_on_supply_chain_status: set = field(
        default_factory=lambda: {"UNTRUSTED"}
    )
    warn_on_supply_chain_status: set = field(
        default_factory=lambda: {"SUSPICIOUS"}
    )
    supply_chain_integrity_minimum: float = 0.45  # below → block

    # ── Global ────────────────────────────────────────────────────────────────
    enable_sanitizer: bool = True
    max_prompt_length: int = 8_192          # characters


# Default policy (can be overridden at runtime)
DEFAULT_POLICY = PolicyConfig()


# ─────────────────────────────────────────────────────────────────────────────
# DECISION RESULT
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PolicyDecision:
    blocked: bool
    reason: str                  # Human-readable explanation
    violations: list = field(default_factory=list)
    warnings: list  = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# SANITIZER — strips dangerous tokens from prompt / context
# ─────────────────────────────────────────────────────────────────────────────

# Tokens that must be removed before forwarding to the LLM
_SANITIZE_PATTERNS = [
    # Prompt delimiter injection
    (re.compile(r'<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>', re.I), ""),
    (re.compile(r'\[/?INST\]|<</?SYS>>', re.I), ""),
    (re.compile(r'<\/?s>', re.I), ""),
    # Explicit trigger tokens
    (re.compile(r'\[TRIGGER:[^\]]{0,40}\]', re.I), "[REDACTED]"),
    (re.compile(r'@@TRIGGER@@|<POISON>|\bTRIGGER_WORD\b|\bBACKDOOR_TOKEN\b', re.I), "[REDACTED]"),
    # Direct injection prefixes
    (re.compile(r'(?i)(ignore (previous|all|prior) instructions?[:\s]*)', re.I), ""),
    (re.compile(r'(?i)(override (your )?(system )?prompt[:\s]*)', re.I), ""),
    # Base64 blobs longer than 40 chars (likely encoded payloads)
    (re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'), "[BASE64_REDACTED]"),
]

def sanitize_text(text: str) -> str:
    """Remove known injection tokens and dangerous delimiters from text."""
    for pattern, replacement in _SANITIZE_PATTERNS:
        text = pattern.sub(replacement, text)
    # Collapse excess whitespace
    text = re.sub(r'\s{3,}', ' ', text).strip()
    return text


# ─────────────────────────────────────────────────────────────────────────────
# POLICY ENGINE CLASS
# ─────────────────────────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Central authority that combines detector results into a final BLOCK/ALLOW
    decision and applies text sanitization.
    """

    def __init__(self, config: PolicyConfig = DEFAULT_POLICY):
        self.config = config

    # ── Prompt evaluation ─────────────────────────────────────────────────────
    def _evaluate_prompt(self, prompt_result) -> tuple[list, list]:
        violations, warnings = [], []
        sev = prompt_result.severity
        if sev in self.config.block_on_prompt_severity:
            violations.append(
                f"[PROMPT INJECTION] Severity={sev} — {prompt_result.explanation}"
            )
        elif sev in self.config.warn_on_prompt_severity:
            warnings.append(
                f"[PROMPT INJECTION] Severity={sev} — {prompt_result.explanation}"
            )
        return violations, warnings

    # ── Dataset evaluation ────────────────────────────────────────────────────
    def _evaluate_dataset(self, dataset_result) -> tuple[list, list]:
        violations, warnings = [], []
        if dataset_result is None:
            return violations, warnings
        if dataset_result.mitigation_action in self.config.block_on_dataset_action:
            violations.append(
                f"[DATASET POISONING] Action={dataset_result.mitigation_action} "
                f"anomaly_score={dataset_result.anomaly_score:.2f} "
                f"— {'; '.join(dataset_result.details[:3])}"
            )
        return violations, warnings

    # ── Supply chain evaluation ───────────────────────────────────────────────
    def _evaluate_supply_chain(self, sc_result) -> tuple[list, list]:
        violations, warnings = [], []
        if sc_result is None:
            return violations, warnings
        status = sc_result.provenance_status
        score  = sc_result.integrity_score
        if status in self.config.block_on_supply_chain_status or score < self.config.supply_chain_integrity_minimum:
            violations.append(
                f"[SUPPLY CHAIN] Status={status} integrity_score={score:.2f} "
                f"— {'; '.join(sc_result.flags[:3])}"
            )
        elif status in self.config.warn_on_supply_chain_status:
            warnings.append(
                f"[SUPPLY CHAIN] Status={status} integrity_score={score:.2f} "
                f"— {'; '.join(sc_result.flags[:2])}"
            )
        return violations, warnings

    # ── Main evaluate ─────────────────────────────────────────────────────────
    def evaluate(
        self,
        prompt_result,
        dataset_result=None,
        sc_result=None,
    ) -> PolicyDecision:
        """
        Evaluate all detector results and produce a final policy decision.

        Args:
            prompt_result:   PromptScanResult from detector_prompt.scan_prompt()
            dataset_result:  DatasetScanResult (single) or None
            sc_result:       SupplyChainResult or None

        Returns:
            PolicyDecision with blocked flag, reason, violations, and warnings.
        """
        all_violations, all_warnings = [], []

        pv, pw = self._evaluate_prompt(prompt_result)
        all_violations.extend(pv)
        all_warnings.extend(pw)

        dv, dw = self._evaluate_dataset(dataset_result)
        all_violations.extend(dv)
        all_warnings.extend(dw)

        sv, sw = self._evaluate_supply_chain(sc_result)
        all_violations.extend(sv)
        all_warnings.extend(sw)

        blocked = bool(all_violations)
        if blocked:
            reason = f"Request BLOCKED — {len(all_violations)} policy violation(s) detected."
        elif all_warnings:
            reason = f"Request ALLOWED with {len(all_warnings)} warning(s)."
        else:
            reason = "Request PASSED all policy checks."

        return PolicyDecision(
            blocked=blocked,
            reason=reason,
            violations=all_violations,
            warnings=all_warnings,
        )

    # ── Sanitize text ─────────────────────────────────────────────────────────
    def sanitize(self, text: str) -> str:
        if not self.config.enable_sanitizer:
            return text
        sanitized = sanitize_text(text)
        # Enforce max length
        return sanitized[: self.config.max_prompt_length]

    # ── Compute confidence ────────────────────────────────────────────────────
    def compute_confidence(
        self,
        prompt_result,
        dataset_result=None,
        sc_result=None,
    ) -> float:
        """
        Return 0.0–1.0 confidence that the request is SAFE.
        (inverse of combined threat scores)
        """
        scores = [1.0 - prompt_result.risk_score]
        if dataset_result:
            scores.append(1.0 - dataset_result.anomaly_score)
        if sc_result:
            scores.append(sc_result.integrity_score)
        return round(sum(scores) / len(scores), 4)
