# Arena — a self-hardening security loop for AI-era apps

Arena stands up a deliberately vulnerable company app, turns a team of AI **attacker**
agents loose on it over real HTTP, and lets a team of AI **defender** agents rewrite the
app's defenses live — round after round — until the attacks stop working. Every attack,
patch, and score is measured on a real localhost target with synthetic data, and the final
result is proven on a held-out set of attacks the agents never saw.

Dashboard: `http://127.0.0.1:5001` · Vulnerable target app: `http://127.0.0.1:5002`

---

## The problem — and why it matters now

Anyone can now ship an app in a weekend. LLMs write the code, the glue, and the deploy
script, and the result *works* — it logs people in, answers questions, serves data. What it
almost never does is survive contact with an attacker. The scaffolding these tools emit ships
with the same quiet holes every time: string-built SQL, unescaped output, no real
authorization check, a keyword "firewall" that feels safe and blocks nothing, tokens that are
never verified, an AI assistant that will read out another customer's records if you phrase it
politely.

The people shipping these apps are, by definition, not the people who can spot those holes.
And the volume of this software is exploding faster than any human security team can review it.
Checklists and static scanners catch known string patterns; they don't play the actual
cat-and-mouse — attacker adapts, defender responds, attacker adapts again — that decides
whether an app is safe. **That loop is the thing that's missing, and it's the thing that has to
be automated.**

## How Arena solves it

Arena runs the whole adversarial loop end to end, with no human in it, against a live target:

1. **A real, vulnerable target app** (Flask + SQLite, 100% synthetic data) exposes the surfaces
   that actually get breached: `/login`, `/search`, `/profile`, `/account/<id>`, `/invoices`,
   `/api/me` (JWT), `/download`, and an LLM `/chat` assistant with company records.
2. **A master attacker agent** studies what has leaked so far and directs **specialist
   attackers** — SQLi, XSS, access/IDOR, prompt injection, traversal, token forgery, flooding —
   that fire *real HTTP requests* and adapt their payloads to whatever defense is currently live.
3. **Outcome oracles** decide ground truth honestly: a browser actually executes the XSS marker,
   a canary record actually comes back, a JWT is actually accepted. An SQL error is not a
   compromise; a refused jailbreak is not.
4. **A master defender agent** reads the exact breach evidence and directs **specialist
   defenders** that rewrite the four defense modules (rate limiter, WAF, access control, crypto).
5. **A deterministic verifier** gates every proposed patch: it must block what broke in, must
   not break a single legitimate user, and must not regress. Only then does it go live.
6. **A reserved holdout** of attacks the agents never saw scores the final result, so
   "improvement" means generalization, not memorization.

## What makes our approach different

- **It attacks a real running app, not a prompt.** Most "AI security" demos score a model on a
  static list of malicious strings. Arena sends live requests to live endpoints and reads live
  responses. A defense only counts when the real request stops working.

- **The defender rewrites the app, and the fix is provably safe.** The agent's output is never
  executed as arbitrary Python — it is validated *policy data* compiled into real, running
  defense code. A patch that would break a real customer is rejected by the verifier before it
  can ship. A deny-everything "defense" can't win, because serving 9/9 legitimate users is a
  gate, not a bonus.

- **The improvement is emergent, not scripted.** The app starts from the posture a vibe-coded
  app actually ships with — a shallow keyword filter and nothing real. We do not hardcode which
  fix lands when; a subsystem is hardened only after the attacker has genuinely breached it, so
  the round-over-round curve is produced by the agents, not by us. You watch the attacker *mutate
  around* each patch (`' OR '1'='1'` → `' OR 2=2 --`, `<script>` → `<svg onload>`) until the
  structural fix finally holds.

- **You can watch it happen in real browsers.** Starting a run opens tiled Chrome windows, each
  an agent driving the real app's UI — breaking in (red) against the naive app, then blocked
  (green) against the hardened one. Nothing is faked for the camera.

- **Real parallelism and full provenance.** Specialist attackers and defenders run concurrently
  on one shared Luminal/DeepSeek client; every agent call, request, payload, patch diff, and
  score is persisted and streamed, so any result can be opened and inspected.

---

## Run it

```bash
uv sync                 # or: pip install flask httpx openai playwright
python server.py        # dashboard :5001 · target :5002
```

`.env` must contain `LUMINAL_API_KEY`. Optional: `LLM_BASE_URL`
(default `https://flash.luminal.cloud/v1`), `LLM_MODEL`
(default `deepseek-ai/DeepSeek-V4.1-Flash`), and `MONGODB_URI` / `MONGODB_DATABASE`
to mirror run events to MongoDB.

In the dashboard:
- **Start live run** (2–8 rounds) — runs the full loop from the naive baseline, opens the real
  attacker browser windows, and ends on the held-out fresh-test score.
- **🤖 Live attack browsers** — re-open the real Chrome attack windows any time.
- **Attack theater** — an aggregate tile view of every vector, red → green, for the live run.
- **Company assistant** — chat with the hardened assistant as any identity.
- Browse the vulnerable app yourself at `http://127.0.0.1:5002` (sign in as *jamie*, then view
  account *morgan* to see broken access on the naive app).
- Click any attack-feed row for the real request/response evidence; **Export evidence**
  downloads the full event log. Live request logs: `.arena-data/target/`.

Headless full-loop check (uses API credits): `python scripts/run_live_check.py 4`.
Regression tests (model stubbed): `python -m unittest tests.test_live`.

## How to read a run

- **Compromised** should fall and **Prevented %** should rise round over round.
- **Authorized tasks 9/9** must stay at 9/9 — if hardening ever breaks a real user it drops,
  and the verifier rejects that patch.
- **Improvement chart** → defense rate per round; the per-round line under it says which
  families were attacked, which layers were patched, the rate change, and the verifier verdict.
- **Fresh tests 0% → N%** → the holdout the agents never saw during optimization. This is the
  real proof it generalizes.
- **Live codebase** → the defense files, diffed against the naive baseline, so you can see
  exactly what the defender rewrote.
- **Agent orchestration** → each bar is one real model call on a shared clock; overlapping bars
  ran in parallel.

Once the whole surface is hardened the curve is flat at the top — later rounds confirm the
attacker's new payloads keep being repelled.

## Honest limits

- Defenses are a bounded policy schema (switches, limits, literal WAF terms) compiled to real
  Python — the agent's output is validated data, never executed arbitrary code. Because the real
  fixes are structural, each subsystem is solved once the attacker exposes it; the multi-round
  curve comes from coverage growing as the attacker probes new families.
- The holdout uses variant payloads of the same families, not entirely new attack classes.
- Not implemented: connection-level Slowloris, host command execution, weak-hash cracking.
- The real-browser windows run a clean before/after (naive vs. hardened); MongoDB mirroring is
  untested without a URI.
