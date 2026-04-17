"""
SentinelLayer — Supply Chain Security Verifier (LLM03)
=======================================================
Realistic model provenance scanner for Hugging Face repositories.

Scoring is signal-driven — no hardcoded per-repo verdict mappings.
All trust decisions derive from:
  • Publisher namespace registry check
  • Namespace typosquatting (Levenshtein edit-distance)
  • Model card / license presence
  • File manifest: pickle, custom Python loaders, safetensors coverage
  • trust_remote_code flag detection
  • LoRA adapter manifest signals
  • Tokenizer config: suspicious added tokens / control sequences
  • SBOM / cryptographic hash availability
  • Weighted deterministic risk scoring

Final action thresholds:
  score ≥ 60  → BLOCK (UNTRUSTED)
  score 30–59 → REVIEW (SUSPICIOUS)
  score < 30  → ALLOW (TRUSTED)
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# TRUSTED PUBLISHER REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

_TRUSTED_ORGS_LOWER: set[str] = {
    "meta-llama",
    "mistralai",
    "google",
    "microsoft",
    "qwen",
    "tiiuae",
    "allenai",
    "stabilityai",
    "huggingface",
    "bigscience",
    "eleutherai",
    "openai",
    "anthropic",
    "cohere",
    "sentence-transformers",
    "deepseek-ai",
    "mosaicml",
    "facebook",
    "bert-base",
    "distilbert",
    "roberta",
    "bartowski",
    "ollama",
}

# For typosquat detection — the orgs attackers most often impersonate
_TYPOSQUAT_TARGETS: list[str] = [
    "meta-llama",
    "mistralai",
    "google",
    "microsoft",
    "qwen",
    "openai",
    "huggingface",
    "stabilityai",
    "allenai",
    "tiiuae",
]

# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL SCORING WEIGHTS
# ─────────────────────────────────────────────────────────────────────────────

# Each key maps to a risk score contribution (additive, capped at 100)
_SIGNAL_WEIGHTS: dict[str, int] = {
    # Execution risk signals
    "trust_remote_code":        40,
    "custom_python_files":      30,
    "pickle_files":             40,
    # Adapter risk signals
    "lora_unknown_publisher":   35,
    "lora_alignment_override":  40,
    "lora_missing_provenance":  20,
    "lora_high_rank":           15,
    "lora_broad_coverage":      15,
    # Serialization signals
    "no_safetensors":           25,
    # Integrity signals
    "missing_model_card":       15,
    "missing_license":          10,
    "missing_hash_signature":   20,
    # Namespace signals
    "unknown_publisher":        25,
    "typosquatted_namespace":   55,
    # Tokenizer signals
    "suspicious_control_tokens": 45,
    "tokenizer_override_tokens": 35,
}

# Action thresholds
_BLOCK_THRESHOLD  = 60
_REVIEW_THRESHOLD = 30

# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY BADGE DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

BADGE_TYPOSQUATTED_NAMESPACE   = "Typosquatted Namespace"
BADGE_CHECKPOINT_EXEC_RISK     = "Checkpoint Execution Risk"
BADGE_UNSAFE_SERIALIZATION     = "Unsafe Serialization"
BADGE_UNVERIFIED_LORA          = "Unverified LoRA Adapter"
BADGE_ALIGNMENT_OVERRIDE       = "Alignment Override Risk"
BADGE_MISSING_MODEL_CARD       = "Missing Model Card"
BADGE_UNKNOWN_PUBLISHER        = "Unknown Publisher"
BADGE_REMOTE_CODE_LOADER       = "Remote Code Loader"
BADGE_TOKENIZER_BACKDOOR       = "Tokenizer Backdoor Risk"
BADGE_MISSING_CRYPTO_SIG       = "Missing Cryptographic Signature"

# ─────────────────────────────────────────────────────────────────────────────
# SUSPICIOUS PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_REPO_PATTERNS = [
    re.compile(r'\bfree\b.*\b(gpt|llama|claude|mistral)\b', re.I),
    re.compile(r'\bunlocked\b|\bunlimited\b|\bunrestricted\b', re.I),
    re.compile(r'\bjailbreak\b|\buncensored\b|\bnolimit\b', re.I),
    re.compile(r'\bcracked\b|\bleaked\b|\bpirated\b', re.I),
    re.compile(r'\btrojan\b|\bbackdoor\b', re.I),
]

_LORA_ALIGNMENT_OVERRIDE_KEYWORDS = [
    "uncensored", "jailbreak", "bypass", "nofilter", "no-filter",
    "unrestricted", "unaligned", "uncensored", "override",
]

_SUSPICIOUS_CONTROL_TOKENS = [
    "SYSTEM_OVERRIDE", "ADMIN_KEY", "DEVELOPER_MODE",
    "TRIGGER_BACKDOOR", "BYPASS_SAFETY", "NO_FILTER",
    "<|system|>", "<<SYS>>", "[INST]",
]

_PICKLE_EXTENSIONS = {".pt", ".pth", ".bin", ".pkl", ".pickle"}
_SAFE_EXTENSIONS   = {".safetensors"}
_PYTHON_LOADER_PATTERNS = [
    re.compile(r'modeling_.*\.py', re.I),
    re.compile(r'configuration_.*\.py', re.I),
    re.compile(r'tokenization_.*\.py', re.I),
]

# ─────────────────────────────────────────────────────────────────────────────
# RESULT DATACLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SupplyChainResult:
    provenance_status: str          # "TRUSTED" | "SUSPICIOUS" | "UNTRUSTED"
    integrity_score: float          # 0.0 – 1.0 (higher = more trustworthy)
    trusted_source: bool
    flags: list[str] = field(default_factory=list)
    badges: list[str] = field(default_factory=list)
    sbom_hash: Optional[str] = None
    sbom_verified: bool = False
    recommended_action: str = "ALLOW"
    risk_score: int = 0             # raw additive score (0–100+)
    signal_breakdown: dict = field(default_factory=dict)

    # Dimension scores (for frontend display)
    provenance_score: str = "HIGH"   # HIGH / MEDIUM / LOW
    adapter_risk: str = "LOW"        # LOW / MEDIUM / HIGH
    execution_risk: str = "LOW"      # LOW / MEDIUM / HIGH
    serialization_risk: str = "LOW"  # LOW / MEDIUM / HIGH
    publisher_trust: str = "KNOWN"   # KNOWN / UNKNOWN


# ─────────────────────────────────────────────────────────────────────────────
# LEVENSHTEIN DISTANCE
# ─────────────────────────────────────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def _detect_typosquatting(namespace: str) -> Optional[str]:
    """Return the target org if namespace is a likely typosquat, else None."""
    ns = namespace.lower()
    if ns in _TRUSTED_ORGS_LOWER:
        return None
    for target in _TYPOSQUAT_TARGETS:
        dist = _levenshtein(ns, target)
        if 0 < dist <= 2:
            return target
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SUB-SCANNERS
# ─────────────────────────────────────────────────────────────────────────────

def scan_lora_adapter_manifest(
    adapter_name: Optional[str],
    publisher_trusted: bool,
) -> tuple[int, list[str], list[str]]:
    """
    Evaluate LoRA adapter metadata signals.
    Returns (risk_score_contribution, flags, badges).
    """
    if not adapter_name:
        return 0, [], []

    score = 0
    flags: list[str] = []
    badges: list[str] = []

    # Unknown publisher
    parts = adapter_name.split("/")
    org = parts[0].lower() if len(parts) >= 2 else ""
    if org and org not in _TRUSTED_ORGS_LOWER:
        score += _SIGNAL_WEIGHTS["lora_unknown_publisher"]
        flags.append(f"LoRA adapter from unverified publisher: '{org}'")
        badges.append(BADGE_UNVERIFIED_LORA)

    # Alignment override keywords in name
    name_lower = adapter_name.lower()
    override_hits = [kw for kw in _LORA_ALIGNMENT_OVERRIDE_KEYWORDS if kw in name_lower]
    if override_hits:
        score += _SIGNAL_WEIGHTS["lora_alignment_override"]
        flags.append(f"LoRA name contains alignment-override keywords: {override_hits[:3]}")
        if BADGE_ALIGNMENT_OVERRIDE not in badges:
            badges.append(BADGE_ALIGNMENT_OVERRIDE)

    # Missing provenance metadata (simulated by checking name structure)
    if len(parts) < 2 or len(parts[0]) < 2:
        score += _SIGNAL_WEIGHTS["lora_missing_provenance"]
        flags.append("LoRA adapter has no organization prefix — provenance unverifiable")

    return score, flags, badges


def scan_tokenizer_config(
    tokenizer_config: Optional[dict],
) -> tuple[int, list[str], list[str]]:
    """
    Scan tokenizer configuration for backdoor / injection signals.
    Returns (risk_score_contribution, flags, badges).
    """
    if not tokenizer_config:
        return 0, [], []

    score = 0
    flags: list[str] = []
    badges: list[str] = []

    # Check added tokens
    added_tokens = tokenizer_config.get("added_tokens", [])
    if isinstance(added_tokens, list):
        for tok in added_tokens:
            tok_str = str(tok).upper()
            hits = [ct for ct in _SUSPICIOUS_CONTROL_TOKENS if ct.upper() in tok_str]
            if hits:
                score += _SIGNAL_WEIGHTS["suspicious_control_tokens"]
                flags.append(f"Suspicious control token in tokenizer: {tok_str[:50]}")
                badges.append(BADGE_TOKENIZER_BACKDOOR)
                break

    # Check special tokens map
    special_map = tokenizer_config.get("special_tokens_map", {})
    for key, val in special_map.items():
        val_str = str(val).upper()
        if any(ct.upper() in val_str for ct in _SUSPICIOUS_CONTROL_TOKENS):
            score += _SIGNAL_WEIGHTS["tokenizer_override_tokens"]
            flags.append(f"Override token in special_tokens_map key '{key}': {val_str[:40]}")
            if BADGE_TOKENIZER_BACKDOOR not in badges:
                badges.append(BADGE_TOKENIZER_BACKDOOR)

    return score, flags, badges


def scan_repo_file_manifest(
    file_list: Optional[list[str]],
    trust_remote_code: bool = False,
) -> tuple[int, list[str], list[str]]:
    """
    Inspect repository file manifest for execution and serialization risks.
    Returns (risk_score_contribution, flags, badges).
    """
    score = 0
    flags: list[str] = []
    badges: list[str] = []

    # trust_remote_code flag
    if trust_remote_code:
        score += _SIGNAL_WEIGHTS["trust_remote_code"]
        flags.append("Repository requires trust_remote_code=True — executes arbitrary Python")
        badges.append(BADGE_REMOTE_CODE_LOADER)

    if not file_list:
        return score, flags, badges

    files_lower = [f.lower() for f in file_list]

    # Pickle / unsafe checkpoint files
    pickle_found = [f for f in file_list if any(f.lower().endswith(ext) for ext in _PICKLE_EXTENSIONS)]
    safe_found   = [f for f in file_list if f.lower().endswith(".safetensors")]

    if pickle_found:
        score += _SIGNAL_WEIGHTS["pickle_files"]
        flags.append(f"Pickle-format checkpoints detected ({len(pickle_found)} file(s)): {pickle_found[:2]}")
        badges.append(BADGE_CHECKPOINT_EXEC_RISK)

    if pickle_found and not safe_found:
        score += _SIGNAL_WEIGHTS["no_safetensors"]
        flags.append("No safetensors alternative — only pickle-format weights available")
        if BADGE_UNSAFE_SERIALIZATION not in badges:
            badges.append(BADGE_UNSAFE_SERIALIZATION)

    # Custom Python execution files
    python_loaders = []
    for fname in file_list:
        for pat in _PYTHON_LOADER_PATTERNS:
            if pat.search(fname):
                python_loaders.append(fname)
                break
    if python_loaders:
        score += _SIGNAL_WEIGHTS["custom_python_files"]
        flags.append(f"Custom Python execution files detected: {python_loaders[:3]}")
        if BADGE_REMOTE_CODE_LOADER not in badges:
            badges.append(BADGE_REMOTE_CODE_LOADER)

    return score, flags, badges


# ─────────────────────────────────────────────────────────────────────────────
# SBOM SIMULATION
# ─────────────────────────────────────────────────────────────────────────────

def _generate_sbom_hash(model_name: str, model_card: Optional[str]) -> str:
    payload = f"{model_name}:{model_card or 'NO_CARD'}"
    return hashlib.sha256(payload.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────────────────────────────────────

def scan_repo(
    repo_id: str,
    model_card: Optional[str] = None,
    has_hash_signature: bool = False,
    has_license: bool = True,
    file_list: Optional[list[str]] = None,
    lora_adapter_name: Optional[str] = None,
    tokenizer_config: Optional[dict] = None,
    trust_remote_code: bool = False,
    is_deprecated: bool = False,
    provided_sbom_hash: Optional[str] = None,
    extra_metadata: Optional[dict] = None,
) -> SupplyChainResult:
    """
    Dynamically compute supply-chain trust for a Hugging Face repository.
    All scoring is signal-driven — no hardcoded per-repo verdict mappings.

    Args:
        repo_id:            Full HF repo ID e.g. "meta-llama/Llama-3-8B"
        model_card:         README/model card text (None = missing)
        has_hash_signature: Whether model has published SHA hash
        has_license:        Whether license file present
        file_list:          List of filenames in repository
        lora_adapter_name:  Optional LoRA adapter repo ID
        tokenizer_config:   Dict parsed from tokenizer_config.json / added_tokens.json
        trust_remote_code:  Whether repo requires trust_remote_code=True
        is_deprecated:      Whether repo is marked deprecated
        provided_sbom_hash: Pre-computed SBOM to verify
        extra_metadata:     Additional metadata dict for red-flag scanning

    Returns:
        SupplyChainResult with dynamic scoring, badges, and explainable flags.
    """
    total_score = 0
    flags: list[str] = []
    badges: list[str] = []
    signal_breakdown: dict[str, int] = {}

    # ── Parse namespace ───────────────────────────────────────────────────────
    parts = repo_id.strip().split("/")
    namespace = parts[0].lower() if len(parts) >= 2 else ""
    model_slug = parts[-1].lower() if parts else repo_id.lower()

    # ── 1. Namespace trust ────────────────────────────────────────────────────
    publisher_known = namespace in _TRUSTED_ORGS_LOWER if namespace else False

    if not publisher_known:
        pts = _SIGNAL_WEIGHTS["unknown_publisher"]
        total_score += pts
        signal_breakdown["unknown_publisher"] = pts
        flags.append(f"Publisher namespace '{namespace or '(none)'}' not in trusted registry")
        badges.append(BADGE_UNKNOWN_PUBLISHER)

    # ── 2. Typosquatting detection ────────────────────────────────────────────
    typosquat_target = _detect_typosquatting(namespace) if namespace else None
    if typosquat_target:
        pts = _SIGNAL_WEIGHTS["typosquatted_namespace"]
        total_score += pts
        signal_breakdown["typosquatted_namespace"] = pts
        flags.append(
            f"Possible typosquatting: '{namespace}' is edit-distance ≤2 from "
            f"trusted org '{typosquat_target}'"
        )
        badges.append(BADGE_TYPOSQUATTED_NAMESPACE)

    # ── 3. Suspicious repo name patterns ─────────────────────────────────────
    for pat in _SUSPICIOUS_REPO_PATTERNS:
        if pat.search(repo_id):
            pts = 30
            total_score += pts
            signal_breakdown[f"suspicious_pattern_{pat.pattern[:20]}"] = pts
            flags.append(f"Suspicious keyword pattern in repo name: '{pat.pattern}'")
            if BADGE_UNKNOWN_PUBLISHER not in badges:
                badges.append(BADGE_UNKNOWN_PUBLISHER)

    # ── 4. Model card presence ────────────────────────────────────────────────
    if model_card is None or len(model_card.strip()) < 50:
        pts = _SIGNAL_WEIGHTS["missing_model_card"]
        total_score += pts
        signal_breakdown["missing_model_card"] = pts
        flags.append("Model card absent or severely incomplete (< 50 chars)")
        badges.append(BADGE_MISSING_MODEL_CARD)
    else:
        card_lower = model_card.lower()
        if any(kw in card_lower for kw in ["jailbreak", "uncensored", "no filter", "bypass"]):
            pts = 25
            total_score += pts
            signal_breakdown["model_card_red_flags"] = pts
            flags.append("Model card contains red-flag language (jailbreak/uncensored/bypass)")
            badges.append(BADGE_ALIGNMENT_OVERRIDE)

    # ── 5. License presence ───────────────────────────────────────────────────
    if not has_license:
        pts = _SIGNAL_WEIGHTS["missing_license"]
        total_score += pts
        signal_breakdown["missing_license"] = pts
        flags.append("No license file detected — redistribution and usage terms unclear")

    # ── 6. Hash / SBOM signature ──────────────────────────────────────────────
    if not has_hash_signature:
        pts = _SIGNAL_WEIGHTS["missing_hash_signature"]
        total_score += pts
        signal_breakdown["missing_hash_signature"] = pts
        flags.append("No cryptographic hash signature for model weights")
        badges.append(BADGE_MISSING_CRYPTO_SIG)

    sbom_hash = _generate_sbom_hash(repo_id, model_card)
    sbom_verified = (provided_sbom_hash == sbom_hash) if provided_sbom_hash else False
    if provided_sbom_hash and not sbom_verified:
        flags.append("SBOM hash mismatch — model integrity cannot be confirmed")
        total_score += 30

    # ── 7. File manifest scan ─────────────────────────────────────────────────
    fm_score, fm_flags, fm_badges = scan_repo_file_manifest(file_list, trust_remote_code)
    total_score += fm_score
    flags.extend(fm_flags)
    for b in fm_badges:
        if b not in badges:
            badges.append(b)
    if fm_score:
        signal_breakdown["file_manifest"] = fm_score

    # ── 8. LoRA adapter scan ──────────────────────────────────────────────────
    la_score, la_flags, la_badges = scan_lora_adapter_manifest(lora_adapter_name, publisher_known)
    total_score += la_score
    flags.extend(la_flags)
    for b in la_badges:
        if b not in badges:
            badges.append(b)
    if la_score:
        signal_breakdown["lora_adapter"] = la_score

    # ── 9. Tokenizer config scan ──────────────────────────────────────────────
    tc_score, tc_flags, tc_badges = scan_tokenizer_config(tokenizer_config)
    total_score += tc_score
    flags.extend(tc_flags)
    for b in tc_badges:
        if b not in badges:
            badges.append(b)
    if tc_score:
        signal_breakdown["tokenizer_config"] = tc_score

    # ── 10. Extra metadata red flags ──────────────────────────────────────────
    if extra_metadata:
        red_flag_vals = {"backdoor", "trojan", "poison", "adversarial", "injected"}
        for k, v in extra_metadata.items():
            if any(rf in str(v).lower() or rf in k.lower() for rf in red_flag_vals):
                pts = 35
                total_score += pts
                signal_breakdown[f"metadata_{k[:20]}"] = pts
                flags.append(f"Red-flag value in metadata field '{k}'")

    # ── 11. Deprecated model ──────────────────────────────────────────────────
    if is_deprecated:
        total_score += 10
        signal_breakdown["deprecated"] = 10
        flags.append("Model is deprecated — may contain unpatched vulnerabilities")

    # ─────────────────────────────────────────────────────────────────────────
    # Compute dimension risk labels
    # ─────────────────────────────────────────────────────────────────────────
    exec_pts = signal_breakdown.get("file_manifest", 0)
    exec_pts += _SIGNAL_WEIGHTS["trust_remote_code"] if trust_remote_code else 0
    if exec_pts >= 50:
        execution_risk = "HIGH"
    elif exec_pts >= 20:
        execution_risk = "MEDIUM"
    else:
        execution_risk = "LOW"

    adapter_pts = signal_breakdown.get("lora_adapter", 0)
    if adapter_pts >= 50:
        adapter_risk = "HIGH"
    elif adapter_pts >= 20:
        adapter_risk = "MEDIUM"
    else:
        adapter_risk = "LOW"

    serial_pts = signal_breakdown.get("file_manifest", 0)
    if serial_pts >= 40:
        serialization_risk = "HIGH"
    elif serial_pts >= 20:
        serialization_risk = "MEDIUM"
    else:
        serialization_risk = "LOW"

    # Provenance score
    namespace_pts = signal_breakdown.get("unknown_publisher", 0) + \
                    signal_breakdown.get("typosquatted_namespace", 0)
    if namespace_pts >= 50:
        provenance_score = "LOW"
    elif namespace_pts >= 20:
        provenance_score = "MEDIUM"
    else:
        provenance_score = "HIGH"

    publisher_trust_label = "KNOWN" if publisher_known else "UNKNOWN"

    # ─────────────────────────────────────────────────────────────────────────
    # Final action based on total score
    # ─────────────────────────────────────────────────────────────────────────
    if total_score >= _BLOCK_THRESHOLD:
        provenance_status  = "UNTRUSTED"
        recommended_action = "BLOCK"
    elif total_score >= _REVIEW_THRESHOLD:
        provenance_status  = "SUSPICIOUS"
        recommended_action = "REVIEW"
    else:
        provenance_status  = "TRUSTED"
        recommended_action = "ALLOW"

    trusted_source = provenance_status == "TRUSTED"
    integrity_score = round(max(0.0, 1.0 - min(1.0, total_score / 100.0)), 4)

    return SupplyChainResult(
        provenance_status=provenance_status,
        integrity_score=integrity_score,
        trusted_source=trusted_source,
        flags=flags,
        badges=badges,
        sbom_hash=sbom_hash,
        sbom_verified=sbom_verified,
        recommended_action=recommended_action,
        risk_score=total_score,
        signal_breakdown=signal_breakdown,
        provenance_score=provenance_score,
        adapter_risk=adapter_risk,
        execution_risk=execution_risk,
        serialization_risk=serialization_risk,
        publisher_trust=publisher_trust_label,
    )


# ─────────────────────────────────────────────────────────────────────────────
# BACKWARDS-COMPATIBLE WRAPPER  (used by middleware.py / app.py)
# ─────────────────────────────────────────────────────────────────────────────

def verify_model_provenance(
    model_name: str,
    model_card: Optional[str] = None,
    has_hash_signature: bool = False,
    is_deprecated: bool = False,
    lora_adapter_name: Optional[str] = None,
    provided_sbom_hash: Optional[str] = None,
    extra_metadata: Optional[dict] = None,
) -> SupplyChainResult:
    """Backwards-compatible wrapper around scan_repo()."""
    return scan_repo(
        repo_id=model_name,
        model_card=model_card,
        has_hash_signature=has_hash_signature,
        is_deprecated=is_deprecated,
        lora_adapter_name=lora_adapter_name,
        provided_sbom_hash=provided_sbom_hash,
        extra_metadata=extra_metadata,
    )