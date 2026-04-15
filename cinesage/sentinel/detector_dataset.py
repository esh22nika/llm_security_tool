"""SentinelLayer — Data & Model Poisoning Detector (LLM04)"""
import re, math, hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

_TRIGGER_TOKEN_PATTERN = re.compile(
    r'\[TRIGGER:[^\]]{1,40}\]|@@TRIGGER@@|<POISON>|\bTRIGGER_WORD\b|\bBACKDOOR_TOKEN\b', re.IGNORECASE)

_ANOMALOUS_INSTRUCTION_PATTERNS = [
    re.compile(r'ignore (previous|all|prior) (instructions?|prompts?)', re.IGNORECASE),
    re.compile(r'(override|bypass|disable)\s+(safety|restrictions?|filter)', re.IGNORECASE),
    re.compile(r'act (as|like) (an )?(unfiltered|unrestricted|evil)', re.IGNORECASE),
    re.compile(r'from now on (you|the model) (will|must|should)', re.IGNORECASE),
    re.compile(r'assistant context update|internal indexing tag|content indexing purposes', re.IGNORECASE),
    re.compile(r'(state|output|prepend).{0,80}(full )?(configuration|system prompt|api keys?|credentials?)', re.IGNORECASE),
    re.compile(r'(your current task is superseded|licensing verification requirement)', re.IGNORECASE),
    re.compile(r'system:\s*(you are|your role)', re.IGNORECASE),
    re.compile(r'<\|im_start\|>|<\|im_end\|>|<\|system\|>', re.IGNORECASE),
    re.compile(r'\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>', re.IGNORECASE),
    re.compile(r'(reveal|disclose|leak)\s+(your|the)?\s*(system prompt|instructions?)', re.IGNORECASE),
]

_HIGH_ENTROPY_THRESHOLD = 4.8
_LONG_TOKEN_PATTERN = re.compile(r'\b[A-Za-z0-9+/]{60,}\b')
_SUSPICIOUS_META_KEYS = {"backdoor","trigger","poison","adversarial","injected","manipulated","trojan","hidden_instruction","override","unsafe_label","synthetic_label","mislabeled"}
_UNVERIFIED_SOURCE_TAGS = {"unverified","unknown","anonymous","untrusted","scraped","auto-generated","no_license"}
_POSITIVE_SIGNALS = {"great","good","excellent","wonderful","love","happy","positive","amazing"}
_NEGATIVE_SIGNALS = {"terrible","awful","hate","horrible","worst","bad","negative","disgusting"}

def _heuristic_label_mismatch(record):
    label = str(record.get("label","")).lower()
    text = str(record.get("text",record.get("content",record.get("sentence","")))).lower()
    words = set(text.split())
    pos_count = len(words & _POSITIVE_SIGNALS); neg_count = len(words & _NEGATIVE_SIGNALS)
    if not (pos_count or neg_count): return 0.0
    if label in {"positive","1","pos"} and neg_count > pos_count: return min(1.0, 0.4 + 0.1*neg_count)
    if label in {"negative","0","neg"} and pos_count > neg_count: return min(1.0, 0.4 + 0.1*pos_count)
    return 0.0

def _shannon_entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c,0)+1
    n = len(s)
    return -sum((f/n)*math.log2(f/n) for f in freq.values())

def _check_high_entropy_token(text):
    for match in _LONG_TOKEN_PATTERN.finditer(text):
        if _shannon_entropy(match.group()) > _HIGH_ENTROPY_THRESHOLD: return True
    return False

def _instruction_density_score(text):
    hits = sum(1 for pat in _ANOMALOUS_INSTRUCTION_PATTERNS if pat.search(text))
    sentences = max(1, text.count(".")+text.count("!")+text.count("?"))
    return min(1.0, hits / max(1, sentences/3))

@dataclass
class DatasetScanResult:
    poisoned_record_detected: bool; anomaly_score: float; mitigation_action: str
    details: list = field(default_factory=list); record_fingerprint: Optional[str] = None

def _fingerprint(record):
    raw = str(sorted(record.items())).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]

ANOMALY_FILTER_THRESHOLD = 0.55
ANOMALY_QUARANTINE_THRESHOLD = 0.80

def scan_dataset_record(record):
    details=[]; scores=[]
    text = str(record.get("text",record.get("content",record.get("sentence",""))))
    trigger_matches = _TRIGGER_TOKEN_PATTERN.findall(text)
    if trigger_matches: details.append(f"Trigger tokens found: {trigger_matches[:5]}"); scores.append(1.0)
    instr_score = _instruction_density_score(text)
    if instr_score > 0.0: details.append(f"Anomalous instruction density score: {instr_score:.2f}"); scores.append(instr_score)
    mismatch_score = _heuristic_label_mismatch(record)
    if mismatch_score > 0.0: details.append(f"Label/content mismatch score: {mismatch_score:.2f}"); scores.append(mismatch_score)
    if _check_high_entropy_token(text): details.append("High-entropy token detected (possible obfuscated payload)"); scores.append(0.65)
    metadata = record.get("metadata",{})
    if isinstance(metadata,dict):
        suspicious_keys = {k.lower() for k in metadata.keys()} & _SUSPICIOUS_META_KEYS
        if suspicious_keys: details.append(f"Suspicious metadata keys: {suspicious_keys}"); scores.append(0.85)
    source = str(record.get("source",record.get("dataset_source",""))).lower()
    if any(tag in source for tag in _UNVERIFIED_SOURCE_TAGS): details.append(f"Unverified dataset source tag: '{source}'"); scores.append(0.45)
    if not text.strip(): details.append("Record has empty text/content field"); scores.append(0.3)
    if scores:
        anomaly_score = round(0.6*max(scores) + 0.4*(sum(scores)/len(scores)), 4)
    else:
        anomaly_score = 0.0
    poisoned = anomaly_score >= ANOMALY_FILTER_THRESHOLD
    if anomaly_score >= ANOMALY_QUARANTINE_THRESHOLD: action = "QUARANTINE"
    elif anomaly_score >= ANOMALY_FILTER_THRESHOLD: action = "FILTER"
    else: action = "ALLOW"
    return DatasetScanResult(poisoned_record_detected=poisoned, anomaly_score=anomaly_score,
                             mitigation_action=action, details=details, record_fingerprint=_fingerprint(record))

@dataclass
class BatchScanResult:
    total_records: int; clean_records: int; filtered_records: int
    quarantined_records: int; safe_records: list; scan_details: list

def scan_dataset_batch(records):
    safe,filtered,quarantined,scan_details=[],[],[],[]
    for rec in records:
        result = scan_dataset_record(rec)
        if result.mitigation_action=="ALLOW": safe.append(rec)
        elif result.mitigation_action=="FILTER": filtered.append(rec); scan_details.append(result)
        else: quarantined.append(rec); scan_details.append(result)
    return BatchScanResult(total_records=len(records),clean_records=len(safe),filtered_records=len(filtered),
                           quarantined_records=len(quarantined),safe_records=safe,scan_details=scan_details)
