"""
SentinelLayer — Data & Model Poisoning Detector (LLM04)
========================================================
Scans HuggingFace dataset records BEFORE embedding or retrieval.

Detects:
  • Backdoor trigger tokens  e.g. [TRIGGER:BACKDOOR]
  • Label / content mismatch (heuristic)
  • Anomalous instruction density
  • Suspicious training metadata fields
  • Unverified / missing dataset source tags
  • Adversarial formatting patterns

Returns:
  { poisoned_record_detected, anomaly_score, mitigation_action, details }
"""

import re
import math
import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional


# ─────────────────────────────────────────────────────────────────────────────
# TRIGGER PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

# Explicit backdoor trigger tokens (BadNets / TrojAI style)
_TRIGGER_TOKEN_PATTERN = re.compile(
    r'\[TRIGGER:[^\]]{1,40}\]'          # [TRIGGER:BACKDOOR]
    r'|@@TRIGGER@@'
    r'|<POISON>'
    r'|\bTRIGGER_WORD\b'
    r'|\bBACKDOOR_TOKEN\b',
    re.IGNORECASE
)

# Instruction-like phrases that should not appear in plain data records
_ANOMALOUS_INSTRUCTION_PATTERNS = [
    re.compile(r'ignore (previous|all|prior) (instructions?|prompts?)', re.IGNORECASE),
    re.compile(r'(override|bypass|disable)\s+(safety|restrictions?|filter)', re.IGNORECASE),
    re.compile(r'act (as|like) (an )?(unfiltered|unrestricted|evil)', re.IGNORECASE),
    re.compile(r'from now on (you|the model) (will|must|should)', re.IGNORECASE),
    re.compile(r'system:\s*(you are|your role)', re.IGNORECASE),
    re.compile(r'<\|im_start\|>|<\|im_end\|>|<\|system\|>', re.IGNORECASE),
    re.compile(r'\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>', re.IGNORECASE),
    re.compile(r'(reveal|disclose|leak)\s+(your|the)?\s*(system prompt|instructions?)', re.IGNORECASE),
]

# High-entropy classifier — detects obfuscated / encrypted payloads
_HIGH_ENTROPY_THRESHOLD = 4.8   # bits per char Shannon entropy
_LONG_TOKEN_PATTERN = re.compile(r'\b[A-Za-z0-9+/]{60,}\b')  # suspiciously long single token


# ─────────────────────────────────────────────────────────────────────────────
# SUSPICIOUS METADATA FIELD NAMES
# ─────────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_META_KEYS = {
    "backdoor", "trigger", "poison", "adversarial", "injected",
    "manipulated", "trojan", "hidden_instruction", "override",
    "unsafe_label", "synthetic_label", "mislabeled",
}

_UNVERIFIED_SOURCE_TAGS = {
    "unverified", "unknown", "anonymous", "untrusted",
    "scraped", "auto-generated", "no_license",
}


# ─────────────────────────────────────────────────────────────────────────────
# LABEL/CONTENT MISMATCH HEURISTICS
# ─────────────────────────────────────────────────────────────────────────────

# Simple word sets per sentiment label for mismatch detection
_POSITIVE_SIGNALS = {"great", "good", "excellent", "wonderful", "love", "happy", "positive", "amazing"}
_NEGATIVE_SIGNALS = {"terrible", "awful", "hate", "horrible", "worst", "bad", "negative", "disgusting"}


def _heuristic_label_mismatch(record: dict) -> float:
    """
    Returns a mismatch score 0.0–1.0.
    Checks if the 'label' field conflicts with content sentiment signals.
    """
    label = str(record.get("label", "")).lower()
    text = str(record.get("text", record.get("content", record.get("sentence", "")))).lower()
    words = set(text.split())

    pos_count = len(words & _POSITIVE_SIGNALS)
    neg_count = len(words & _NEGATIVE_SIGNALS)

    if not (pos_count or neg_count):
        return 0.0   # Cannot determine — no signal words

    if label in {"positive", "1", "pos"} and neg_count > pos_count:
        return min(1.0, 0.4 + 0.1 * neg_count)
    if label in {"negative", "0", "neg"} and pos_count > neg_count:
        return min(1.0, 0.4 + 0.1 * pos_count)

    return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# SHANNON ENTROPY
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _check_high_entropy_token(text: str) -> bool:
    for match in _LONG_TOKEN_PATTERN.finditer(text):
        if _shannon_entropy(match.group()) > _HIGH_ENTROPY_THRESHOLD:
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# INSTRUCTION DENSITY
# ─────────────────────────────────────────────────────────────────────────────

def _instruction_density_score(text: str) -> float:
    """
    Returns 0.0–1.0 based on how many adversarial instruction patterns
    are found relative to total sentence count.
    """
    hits = sum(1 for pat in _ANOMALOUS_INSTRUCTION_PATTERNS if pat.search(text))
    sentences = max(1, text.count(".") + text.count("!") + text.count("?"))
    return min(1.0, hits / max(1, sentences / 3))  # normalised


# ─────────────────────────────────────────────────────────────────────────────
# RESULT DATACLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DatasetScanResult:
    poisoned_record_detected: bool
    anomaly_score: float           # 0.0 – 1.0
    mitigation_action: str         # "ALLOW" | "FILTER" | "QUARANTINE"
    details: list = field(default_factory=list)
    record_fingerprint: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# FINGERPRINTING
# ─────────────────────────────────────────────────────────────────────────────

def _fingerprint(record: dict) -> str:
    raw = str(sorted(record.items())).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API — single record scan
# ─────────────────────────────────────────────────────────────────────────────

ANOMALY_FILTER_THRESHOLD     = 0.55   # above → FILTER (remove from RAG)
ANOMALY_QUARANTINE_THRESHOLD = 0.80   # above → QUARANTINE (alert + remove)


def scan_dataset_record(record: dict) -> DatasetScanResult:
    """
    Scan a single HuggingFace dataset record dict for poisoning signals.

    Args:
        record: A dict with at minimum a 'text' or 'content' key and
                optional 'label', 'metadata', 'source' keys.

    Returns:
        DatasetScanResult dataclass.
    """
    details  = []
    scores   = []
    text     = str(record.get("text", record.get("content", record.get("sentence", ""))))

    # ── 1. Trigger token detection ────────────────────────────────────────────
    trigger_matches = _TRIGGER_TOKEN_PATTERN.findall(text)
    if trigger_matches:
        details.append(f"Trigger tokens found: {trigger_matches[:5]}")
        scores.append(1.0)

    # ── 2. Instruction pattern density ───────────────────────────────────────
    instr_score = _instruction_density_score(text)
    if instr_score > 0.0:
        details.append(f"Anomalous instruction density score: {instr_score:.2f}")
        scores.append(instr_score)

    # ── 3. Label / content mismatch ──────────────────────────────────────────
    mismatch_score = _heuristic_label_mismatch(record)
    if mismatch_score > 0.0:
        details.append(f"Label/content mismatch score: {mismatch_score:.2f}")
        scores.append(mismatch_score)

    # ── 4. High-entropy token ────────────────────────────────────────────────
    if _check_high_entropy_token(text):
        details.append("High-entropy token detected (possible obfuscated payload)")
        scores.append(0.65)

    # ── 5. Suspicious metadata keys ──────────────────────────────────────────
    metadata = record.get("metadata", {})
    if isinstance(metadata, dict):
        suspicious_keys = {k.lower() for k in metadata.keys()} & _SUSPICIOUS_META_KEYS
        if suspicious_keys:
            details.append(f"Suspicious metadata keys: {suspicious_keys}")
            scores.append(0.85)

    # ── 6. Unverified source tag ──────────────────────────────────────────────
    source = str(record.get("source", record.get("dataset_source", ""))).lower()
    if any(tag in source for tag in _UNVERIFIED_SOURCE_TAGS):
        details.append(f"Unverified dataset source tag: '{source}'")
        scores.append(0.45)

    # ── 7. Missing critical fields ────────────────────────────────────────────
    if not text.strip():
        details.append("Record has empty text/content field")
        scores.append(0.3)

    # ── Aggregate anomaly score ───────────────────────────────────────────────
    if scores:
        # Weighted max + mean blend
        anomaly_score = round(0.6 * max(scores) + 0.4 * (sum(scores) / len(scores)), 4)
    else:
        anomaly_score = 0.0

    poisoned = anomaly_score >= ANOMALY_FILTER_THRESHOLD

    if anomaly_score >= ANOMALY_QUARANTINE_THRESHOLD:
        action = "QUARANTINE"
    elif anomaly_score >= ANOMALY_FILTER_THRESHOLD:
        action = "FILTER"
    else:
        action = "ALLOW"

    return DatasetScanResult(
        poisoned_record_detected=poisoned,
        anomaly_score=anomaly_score,
        mitigation_action=action,
        details=details,
        record_fingerprint=_fingerprint(record),
    )


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API — batch scan (RAG context list)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BatchScanResult:
    total_records: int
    clean_records: int
    filtered_records: int
    quarantined_records: int
    safe_records: list          # list of original clean record dicts
    scan_details: list          # list of DatasetScanResult for flagged records


def scan_dataset_batch(records: list[dict]) -> BatchScanResult:
    """
    Scan a list of HuggingFace records. Returns only clean records for RAG.

    Args:
        records: list of record dicts.

    Returns:
        BatchScanResult with safe_records filtered for use in RAG.
    """
    safe, filtered, quarantined, scan_details = [], [], [], []

    for rec in records:
        result = scan_dataset_record(rec)
        if result.mitigation_action == "ALLOW":
            safe.append(rec)
        elif result.mitigation_action == "FILTER":
            filtered.append(rec)
            scan_details.append(result)
        else:  # QUARANTINE
            quarantined.append(rec)
            scan_details.append(result)

    return BatchScanResult(
        total_records=len(records),
        clean_records=len(safe),
        filtered_records=len(filtered),
        quarantined_records=len(quarantined),
        safe_records=safe,
        scan_details=scan_details,
    )
