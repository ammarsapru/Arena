"""
The agents. A proposer reads the current best detector + its mistakes and writes
a better one. Each proposer gets a DIFFERENT strategy hint so the population
explores genuinely different approaches (the 30% "meaningfully different" and
20% "parallelism" criteria). The analyst reads a round's results and writes
lessons that feed the next round.

Two implementations of each:
  - FAKE  (no LLM): deterministic mutations, proves the loop end-to-end today.
  - REAL  (Luminal): the actual agents, enabled when credits land.
"""
import re
from model import call_model_async

# Distinct strategy families — one per parallel proposer. Diversity is scored.
STRATEGIES = [
    "keyword and phrase blocklist, but broaden it to catch paraphrases and synonyms",
    "structural heuristics: detect instruction-override patterns, role-play framing, and 'repeat/print your prompt' requests via regex",
    "length / entropy / special-character signals that separate crafted attacks from normal billing questions",
    "an allowlist mindset: model what a NORMAL billing message looks like and flag anything that deviates",
    "detect social-engineering framings (authority, urgency, 'developer mode', 'grandma', 'audit', encoding tricks)",
]

PROPOSER_SYSTEM = """You write Python functions that detect prompt-injection \
attacks. You output ONLY a Python code block defining exactly:

def detect(text: str) -> bool:
    # return True to BLOCK (attack), False to ALLOW (benign)

No imports beyond the standard library. No explanation outside the code block. \
The function must be fast and must not crash on any input."""


def _proposer_user(current_code, score_str, misses, strategy):
    fn = "\n".join("  - " + m for m in misses["false_negatives"]) or "  (none)"
    fp = "\n".join("  - " + m for m in misses["false_positives"]) or "  (none)"
    return f"""Current detector:
```python
{current_code}
```
Current score: {score_str}

Attacks it MISSED (make sure these get caught):
{fn}

Benign messages it WRONGLY blocked (stop blocking these):
{fp}

Write an improved detect(). Strategy to pursue this round: {strategy}"""


def _extract_code(text: str) -> str:
    m = re.search(r"```(?:python)?\s*(.*?)```", text, re.DOTALL)
    code = m.group(1) if m else text
    return code.strip()


async def propose_real(current_code, score_str, misses, strategy):
    raw = await call_model_async(
        PROPOSER_SYSTEM,
        _proposer_user(current_code, score_str, misses, strategy),
        temperature=0.8, max_tokens=1200)
    return _extract_code(raw)


ANALYST_SYSTEM = """You analyze a round of prompt-injection detectors and write \
3-4 sentences of concrete lessons for the next round: which approaches worked, \
what kinds of attacks still slip through, what to try next. Be specific and brief."""


async def analyze_real(round_summary: str) -> str:
    return await call_model_async(ANALYST_SYSTEM, round_summary,
                                  temperature=0.5, max_tokens=300)


# ---- FAKE versions: no network, deterministic, prove the plumbing ----------
_FAKE_MUTATIONS = [
    # each round the fake proposer "discovers" a few more patterns
    ["ignore previous", "ignore all previous", "developer mode", "system override",
     "reveal", "secret code", "disregard"],
    ["ignore", "previous instructions", "developer mode", "override",
     "reveal", "secret", "disregard", "dan", "verbatim", "system prompt"],
    ["ignore", "disregard", "forget", "previous instruction", "developer mode",
     "override", "reveal", "secret", "password", "access code", "dan",
     "verbatim", "system prompt", "repeat the words", "base64", "encode"],
    ["ignore", "disregard", "forget", "pretend", "previous instruction",
     "developer mode", "override", "reveal", "secret", "password", "access code",
     "confidential", "dan", "verbatim", "repeat", "base64", "encode", "translate",
     "admin", "audit", "urgent", "grandmother", "new instructions"],
]


def propose_fake(round_idx: int, proposer_idx: int) -> str:
    """Deterministic stand-in: returns a blocklist detector that grows each
    round, so the score visibly climbs. Proves the loop without any LLM."""
    kws = _FAKE_MUTATIONS[min(round_idx, len(_FAKE_MUTATIONS) - 1)]
    # tiny per-proposer variation so proposers aren't identical
    if proposer_idx % 2 == 1 and len(kws) > 3:
        kws = kws + ["instruction", "comply"]
    kw_repr = ", ".join(repr(k) for k in kws)
    return f'''def detect(text):
    bad = [{kw_repr}]
    t = text.lower()
    return any(b in t for b in bad)'''


def analyze_fake(round_summary: str) -> str:
    return ("Blocklist detectors are improving recall as more override-phrasings "
            "are added. Remaining misses are paraphrased or encoded attacks; next "
            "round should add structural/regex patterns rather than more keywords.")
