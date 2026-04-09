"""SentinelLayer — Supply Chain Security Verifier (LLM03)"""
import re, hashlib
from dataclasses import dataclass, field
from typing import Optional

_TRUSTED_ORGS_LOWER = {"openai","meta-llama","mistralai","google","microsoft","huggingface",
    "bigscience","eleutherai","stability-ai","facebook","allenai","deepseek-ai","cohere",
    "anthropic","sentence-transformers","bert-base","distilbert","roberta","tiiuae","mosaicml",
    "qwen","ollama","bartowski"}

_KNOWN_MODEL_NAMES = ["bert-base-uncased","gpt2","gpt-j-6b","llama-2-7b","llama-3-8b",
    "mistral-7b-v0.1","falcon-7b","mpt-7b","roberta-base","distilbert-base-uncased",
    "all-minilm-l6-v2","qwen2.5-1.5b","qwen2.5-7b"]

_SUSPICIOUS_REPO_PATTERNS = [
    re.compile(r'\bfree\b.*\b(gpt|llama|claude)\b', re.IGNORECASE),
    re.compile(r'\bunlocked\b|\bunlimited\b|\bunrestricted\b', re.IGNORECASE),
    re.compile(r'\bjailbreak\b|\buncensored\b|\bnolimit\b', re.IGNORECASE),
    re.compile(r'\bcracked\b|\bleaked\b|\bpirated\b', re.IGNORECASE),
    re.compile(r'\btrojan\b|\bbackdoor\b|\bhidden\b', re.IGNORECASE),
]
_SUSPICIOUS_LORA_PATTERNS = [
    re.compile(r'jailbreak', re.IGNORECASE), re.compile(r'uncensored', re.IGNORECASE),
    re.compile(r'override', re.IGNORECASE), re.compile(r'bypass', re.IGNORECASE),
    re.compile(r'no.?filter', re.IGNORECASE),
]

def _levenshtein(a, b):
    if a==b: return 0
    if not a: return len(b)
    if not b: return len(a)
    prev = list(range(len(b)+1))
    for i,ca in enumerate(a,1):
        curr=[i]
        for j,cb in enumerate(b,1):
            curr.append(min(prev[j]+1, curr[j-1]+1, prev[j-1]+(ca!=cb)))
        prev=curr
    return prev[-1]

def _detect_typosquatting(repo_id):
    name_part = repo_id.split("/")[-1].lower()
    for known in _KNOWN_MODEL_NAMES:
        known_name = known.split("/")[-1].lower()
        dist = _levenshtein(name_part, known_name)
        if 0 < dist <= max(2, len(known_name)//8): return known
    return None

def _generate_sbom_hash(model_name, model_card):
    payload = f"{model_name}:{model_card or 'NO_CARD'}"
    return hashlib.sha256(payload.encode()).hexdigest()

@dataclass
class SupplyChainResult:
    provenance_status: str; integrity_score: float; trusted_source: bool
    flags: list = field(default_factory=list); sbom_hash: Optional[str] = None
    sbom_verified: bool = False; recommended_action: str = "ALLOW"

def verify_model_provenance(model_name, model_card=None, has_hash_signature=False,
                             is_deprecated=False, lora_adapter_name=None,
                             provided_sbom_hash=None, extra_metadata=None):
    flags=[]; deductions=[]
    parts = model_name.split("/")
    org = parts[0].lower() if len(parts)>=2 else ""
    from_trusted_org = org in _TRUSTED_ORGS_LOWER
    if not from_trusted_org:
        if org: flags.append(f"Model author '{org}' not in trusted org list"); deductions.append(0.3)
        else: flags.append("Model has no org prefix"); deductions.append(0.4)
    if model_card is None or len(model_card.strip())<50:
        flags.append("Model card missing or incomplete"); deductions.append(0.25)
    else:
        if any(kw in model_card.lower() for kw in ["jailbreak","uncensored","no filter","bypass"]):
            flags.append("Model card contains red-flag language"); deductions.append(0.4)
    if not has_hash_signature: flags.append("No cryptographic hash signature"); deductions.append(0.2)
    if is_deprecated: flags.append("Model is deprecated"); deductions.append(0.15)
    for pat in _SUSPICIOUS_REPO_PATTERNS:
        if pat.search(model_name): flags.append(f"Suspicious pattern in repo name"); deductions.append(0.5)
    squatted = _detect_typosquatting(model_name)
    if squatted: flags.append(f"Possible typosquatting: '{model_name}' ~ '{squatted}'"); deductions.append(0.6)
    if lora_adapter_name:
        for pat in _SUSPICIOUS_LORA_PATTERNS:
            if pat.search(lora_adapter_name): flags.append(f"Suspicious LoRA adapter: '{lora_adapter_name}'"); deductions.append(0.55); break
    if extra_metadata:
        meta_lower = {k.lower(): str(v).lower() for k,v in extra_metadata.items()}
        for k,v in meta_lower.items():
            if any(rf in v or rf in k for rf in {"backdoor","trojan","poison","adversarial"}):
                flags.append(f"Red-flag value in metadata '{k}'"); deductions.append(0.7)
    sbom_hash = _generate_sbom_hash(model_name, model_card)
    sbom_verified = provided_sbom_hash == sbom_hash if provided_sbom_hash else False
    if provided_sbom_hash and not sbom_verified: flags.append("SBOM hash mismatch"); deductions.append(0.5)
    total_deduction = min(1.0, sum(deductions))
    integrity_score = round(max(0.0, 1.0-total_deduction), 4)
    if integrity_score >= 0.75 and from_trusted_org: provenance_status = "TRUSTED"
    elif integrity_score >= 0.45: provenance_status = "SUSPICIOUS"
    else: provenance_status = "UNTRUSTED"
    trusted_source = provenance_status=="TRUSTED"
    recommended_action = "BLOCK" if provenance_status=="UNTRUSTED" else ("REVIEW" if provenance_status=="SUSPICIOUS" else "ALLOW")
    return SupplyChainResult(provenance_status=provenance_status, integrity_score=integrity_score,
                             trusted_source=trusted_source, flags=flags, sbom_hash=sbom_hash,
                             sbom_verified=sbom_verified, recommended_action=recommended_action)
