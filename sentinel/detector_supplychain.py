"""
SentinelLayer — Supply Chain Security Verifier (LLM03)
=======================================================
Validates external model dependencies before loading them into production.

Checks:
  • HuggingFace model provenance (author reputation heuristics)
  • Missing / incomplete model cards
  • Missing hash / checksum signatures
  • Model age and deprecation flags
  • Suspicious LoRA adapter configurations
  • Typosquatted repository names (edit-distance attacks)
  • SBOM-style integrity verification simulation

Simulates:
  SBOM-style verification layer for ML model supply chain

Returns:
  { provenance_status, integrity_score, trusted_source, flags, sbom_hash }
"""

import re
import math
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# ALLOW / DENY LISTS
# ─────────────────────────────────────────────────────────────────────────────

# Verified, well-known organizations on HuggingFace
_TRUSTED_ORGS = {
    "openai", "meta-llama", "mistralai", "google", "microsoft",
    "huggingface", "bigscience", "EleutherAI", "stability-ai",
    "facebook", "allenai", "deepseek-ai", "cohere", "anthropic",
    "sentence-transformers", "bert-base", "distilbert", "roberta",
    "tiiuae",   # Falcon
    "mosaicml", # MPT
}
_TRUSTED_ORGS_LOWER = {o.lower() for o in _TRUSTED_ORGS}

# Known legitimate popular base names (for typosquatting comparison)
_KNOWN_MODEL_NAMES = [
    "bert-base-uncased",
    "gpt2",
    "gpt-j-6b",
    "llama-2-7b",
    "llama-3-8b",
    "mistral-7b-v0.1",
    "falcon-7b",
    "mpt-7b",
    "roberta-base",
    "distilbert-base-uncased",
    "all-minilm-l6-v2",
    "sentence-transformers/all-minilm-l6-v2",
]

# Red-flag substrings in repository paths
_SUSPICIOUS_REPO_PATTERNS = [
    re.compile(r'\bfree\b.*\b(gpt|llama|claude)\b', re.IGNORECASE),
    re.compile(r'\bunlocked\b|\bunlimited\b|\bunrestricted\b', re.IGNORECASE),
    re.compile(r'\bjailbreak\b|\buncensored\b|\bnolimit\b', re.IGNORECASE),
    re.compile(r'\bcracked\b|\bleaked\b|\bpirated\b', re.IGNORECASE),
    re.compile(r'\btrojan\b|\bbackdoor\b|\bhidden\b', re.IGNORECASE),
    re.compile(r'\d{3,}k-params\b', re.IGNORECASE),   # suspicious param claims
]

# LoRA adapter red flags
_SUSPICIOUS_LORA_PATTERNS = [
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'uncensored', re.IGNORECASE),
    re.compile(r'override', re.IGNORECASE),
    re.compile(r'bypass', re.IGNORECASE),
    re.compile(r'no.?filter', re.IGNORECASE),
]


# ─────────────────────────────────────────────────────────────────────────────
# LEVENSHTEIN DISTANCE (typosquatting detection)
# ─────────────────────────────────────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
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


def _detect_typosquatting(repo_id: str) -> Optional[str]:
    """
    Return the squatted model name if the repo_id is suspiciously close to a
    known legitimate model name, else None.
    """
    # Normalise: strip org prefix for name comparison
    name_part = repo_id.split("/")[-1].lower()

    for known in _KNOWN_MODEL_NAMES:
        known_name = known.split("/")[-1].lower()
        dist = _levenshtein(name_part, known_name)
        # Short edit distance but not identical → typosquatting candidate
        if 0 < dist <= max(2, len(known_name) // 8):
            return known
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SBOM SIMULATION
# ─────────────────────────────────────────────────────────────────────────────

def _generate_sbom_hash(model_name: str, model_card: Optional[str]) -> str:
    """
    Simulate a deterministic SBOM hash for a model artifact.
    In production this would be replaced by actual weight file checksums.
    """
    payload = f"{model_name}:{model_card or 'NO_CARD'}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _verify_sbom_hash(model_name: str, model_card: Optional[str], provided_hash: Optional[str]) -> bool:
    """Verify a provided SBOM hash against our recomputed one."""
    if not provided_hash:
        return False
    expected = _generate_sbom_hash(model_name, model_card)
    return provided_hash == expected


# ─────────────────────────────────────────────────────────────────────────────
# RESULT DATACLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SupplyChainResult:
    provenance_status: str          # "TRUSTED" | "SUSPICIOUS" | "UNTRUSTED"
    integrity_score: float          # 0.0 – 1.0 (higher = more trustworthy)
    trusted_source: bool
    flags: list = field(default_factory=list)
    sbom_hash: Optional[str] = None
    sbom_verified: bool = False
    recommended_action: str = "ALLOW"


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
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
    """
    Validate a HuggingFace model's supply chain provenance.

    Args:
        model_name:          Full HuggingFace repo ID, e.g. "meta-llama/Llama-2-7b-hf"
        model_card:          Raw model card README text (or None if missing)
        has_hash_signature:  Whether the model has a published sha256 hash
        is_deprecated:       Whether the model is flagged as deprecated
        lora_adapter_name:   Optional LoRA adapter repo ID to validate
        provided_sbom_hash:  Pre-computed SBOM hash to verify against
        extra_metadata:      Additional model metadata dict for inspection

    Returns:
        SupplyChainResult dataclass.
    """
    flags = []
    deductions = []   # integrity point deductions (0.0–1.0 per flag)

    # ── 1. Parse org from model name ─────────────────────────────────────────
    parts = model_name.split("/")
    org = parts[0].lower() if len(parts) >= 2 else ""
    model_slug = model_name.lower()

    # ── 2. Trusted org check ──────────────────────────────────────────────────
    from_trusted_org = org in _TRUSTED_ORGS_LOWER
    if not from_trusted_org:
        if org:
            flags.append(f"Model author '{org}' is not in the trusted organization list")
            deductions.append(0.3)
        else:
            flags.append("Model has no organization prefix (community/anonymous upload)")
            deductions.append(0.4)

    # ── 3. Model card presence ────────────────────────────────────────────────
    if model_card is None or len(model_card.strip()) < 50:
        flags.append("Model card is missing or severely incomplete (< 50 chars)")
        deductions.append(0.25)
    else:
        # Check model card for red-flag language
        card_lower = model_card.lower()
        if any(kw in card_lower for kw in ["jailbreak", "uncensored", "no filter", "bypass"]):
            flags.append("Model card contains red-flag language (jailbreak/uncensored/bypass)")
            deductions.append(0.4)

    # ── 4. Hash signature ──────────────────────────────────────────────────────
    if not has_hash_signature:
        flags.append("No cryptographic hash signature found for model weights")
        deductions.append(0.2)

    # ── 5. Deprecated model ───────────────────────────────────────────────────
    if is_deprecated:
        flags.append("Model is marked as deprecated — may contain unpatched vulnerabilities")
        deductions.append(0.15)

    # ── 6. Suspicious repo name patterns ─────────────────────────────────────
    for pat in _SUSPICIOUS_REPO_PATTERNS:
        if pat.search(model_name):
            flags.append(f"Suspicious pattern in repository name: '{pat.pattern}'")
            deductions.append(0.5)

    # ── 7. Typosquatting detection ────────────────────────────────────────────
    squatted = _detect_typosquatting(model_name)
    if squatted:
        flags.append(
            f"Possible typosquatting: '{model_name}' is very similar to '{squatted}'"
        )
        deductions.append(0.6)

    # ── 8. LoRA adapter validation ────────────────────────────────────────────
    if lora_adapter_name:
        for pat in _SUSPICIOUS_LORA_PATTERNS:
            if pat.search(lora_adapter_name):
                flags.append(f"Suspicious LoRA adapter name: '{lora_adapter_name}'")
                deductions.append(0.55)
                break
        lora_parts = lora_adapter_name.split("/")
        lora_org = lora_parts[0].lower() if len(lora_parts) >= 2 else ""
        if lora_org and lora_org not in _TRUSTED_ORGS_LOWER:
            flags.append(f"LoRA adapter from untrusted source: '{lora_org}'")
            deductions.append(0.35)

    # ── 9. Extra metadata inspection ─────────────────────────────────────────
    if extra_metadata:
        meta_lower = {k.lower(): str(v).lower() for k, v in extra_metadata.items()}
        red_flag_vals = {"backdoor", "trojan", "poison", "adversarial", "injected"}
        for k, v in meta_lower.items():
            if any(rf in v or rf in k for rf in red_flag_vals):
                flags.append(f"Red-flag value in metadata field '{k}': '{v}'")
                deductions.append(0.7)

    # ── 10. SBOM verification ─────────────────────────────────────────────────
    sbom_hash = _generate_sbom_hash(model_name, model_card)
    sbom_verified = _verify_sbom_hash(model_name, model_card, provided_sbom_hash)
    if provided_sbom_hash and not sbom_verified:
        flags.append("SBOM hash mismatch — model integrity cannot be confirmed")
        deductions.append(0.5)

    # ── Compute integrity score ───────────────────────────────────────────────
    total_deduction = min(1.0, sum(deductions))
    integrity_score = round(max(0.0, 1.0 - total_deduction), 4)

    # ── Determine provenance status ───────────────────────────────────────────
    if integrity_score >= 0.75 and from_trusted_org:
        provenance_status = "TRUSTED"
    elif integrity_score >= 0.45:
        provenance_status = "SUSPICIOUS"
    else:
        provenance_status = "UNTRUSTED"

    trusted_source = provenance_status == "TRUSTED"

    # ── Recommended action ────────────────────────────────────────────────────
    if provenance_status == "UNTRUSTED":
        recommended_action = "BLOCK"
    elif provenance_status == "SUSPICIOUS":
        recommended_action = "REVIEW"
    else:
        recommended_action = "ALLOW"

    return SupplyChainResult(
        provenance_status=provenance_status,
        integrity_score=integrity_score,
        trusted_source=trusted_source,
        flags=flags,
        sbom_hash=sbom_hash,
        sbom_verified=sbom_verified,
        recommended_action=recommended_action,
    )
