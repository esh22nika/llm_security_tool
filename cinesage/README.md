# CineSage — Damn Vulnerable LLM Application
## Built on SentinelLayer Security Middleware

A deliberately vulnerable AI movie recommendation app designed to
demonstrate OWASP LLM Top 10 attacks and defenses in a realistic setting.

---

## Setup

```bash
pip install -r requirements.txt
python run.py
# Open http://localhost:8000
```

## Attack Surface

### LLM01 — Prompt Injection
Use the Attack Playbook in the sidebar to fire pre-built payloads.
With SentinelLayer OFF, attacks succeed and reveal the system prompt.
With SentinelLayer ON, they are blocked and explained.

### LLM04 — Data & Model Poisoning
Use the Poison Lab tab to inject malicious records into the live RAG
database. The dataset already contains 3 pre-seeded poison records:
- POISON_001: Backdoor trigger token
- POISON_002: Instruction injection
- POISON_003: Metadata backdoor + label mismatch

### LLM03 — Supply Chain
Use the Model Probe tab to verify HuggingFace model provenance.
Try typosquatted names like `llma-2-7b/fake` or `free-gpt4-unlocked/uncensored`.

## Architecture

```
User Input
    ↓
[SentinelLayer Toggle]
    ├── OFF: Raw LLM (attacks succeed)
    └── ON:
        ├── LLM01: Prompt Injection Scan
        ├── LLM04: Dataset Poisoning Scan (RAG chunk)
        ├── LLM03: Supply Chain Verification
        ├── Policy Engine (block/warn/allow)
        └── Sanitizer → Safe LLM call
```

## Notes
- Run ONLY on localhost. Never expose to internet.
- No real LLM API keys needed — responses are simulated for demo purposes.
- To use a real Ollama/llama.cpp backend, replace `simulate_llm_response()` in main.py.
