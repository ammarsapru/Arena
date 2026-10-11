"""
Layer A — the scored backbone. Defender agents evolve injection detectors over
rounds; the final winner is tested ONCE on held-out data it never saw.

Run it today with no LLM and no network:
    python run_layer_a.py --fake

Run it for real once Luminal credits land (set LLM_* env vars first):
    LLM_BASE_URL=... LLM_API_KEY=... LLM_MODEL=deepseek-ai/DeepSeek-V4.1-Flash \
        python run_layer_a.py --real

Use the big real dataset instead of the embedded sample:
    python run_layer_a.py --fake --hf deepset/prompt-injections

This maps straight onto the judging criteria:
  40% improvement : baseline F1 vs final F1 ON HOLDOUT (printed at the end)
  30% loop design : distinct strategies per proposer + analyst feedback each round
  20% parallelism : proposers run concurrently (asyncio) in --real mode
  10% demo        : run.json carries the full evolution tree for the dashboard
"""
import argparse, asyncio
import dataset as D
import baseline
from scorer import score, misclassified, run_detector_code
from store import Store
import agents


def make_detector(code):
    return run_detector_code(code)


async def run(mode, rounds, n_proposers, hf_name, k):
    # ---- data: train is what agents optimize on; holdout is the fresh test
    records = D.load_hf(hf_name) if hf_name else D.load_sample()
    train, holdout = D.split(records, holdout_frac=0.3, seed=42)
    print(f"dataset: {len(records)} records  (train {len(train)} / holdout {len(holdout)})")

    store = Store()

    # ---- baseline: the starting line
    base_fn = make_detector(baseline.BASELINE_CODE)
    base_score = score(base_fn, train)
    base_doc = store.add_candidate(0, -1, "baseline", None,
                                   baseline.BASELINE_CODE, base_score)
    print(f"\n[baseline]  {base_score}")

    best = base_doc
    lessons = "(none yet)"

    # ---- the improvement loop
    for rnd in range(1, rounds + 1):
        parent = best
        strategies = [agents.STRATEGIES[i % len(agents.STRATEGIES)]
                      for i in range(n_proposers)]

        if mode == "real":
            # PARALLEL proposers — the 20% criterion, visibly concurrent
            miss = misclassified(make_detector(parent["code"]), train)
            tasks = [agents.propose_real(parent["code"], str(parent["score"]),
                                         miss, strategies[i])
                     for i in range(n_proposers)]
            codes = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            codes = [agents.propose_fake(rnd, i) for i in range(n_proposers)]

        round_docs = []
        for i, code in enumerate(codes):
            if isinstance(code, Exception):
                continue
            try:
                fn = make_detector(code)
                sc = score(fn, train)
            except Exception:
                continue
            doc = store.add_candidate(rnd, i, strategies[i], parent["_id"], code, sc)
            round_docs.append(doc)

        if not round_docs:
            print(f"[round {rnd}] no valid proposals, stopping")
            break

        round_best = max(round_docs, key=lambda d: d["score"]["f1"])
        if round_best["score"]["f1"] > best["score"]["f1"]:
            best = round_best

        # ---- analyst: feedback that steers the next round (30% criterion)
        summary = (f"Round {rnd}. Best F1 this round {round_best['score']['f1']:.3f}. "
                   f"Scores: {[round(d['score']['f1'],3) for d in round_docs]}.")
        lessons = (await agents.analyze_real(summary)) if mode == "real" \
                  else agents.analyze_fake(summary)
        store.add_lesson(rnd, lessons)

        print(f"[round {rnd}]  best F1={round_best['score']['f1']:.3f}  "
              f"(running best {best['score']['f1']:.3f})  "
              f"proposals={len(round_docs)}")

    # ---- THE HEADLINE: best detector on the held-out fresh test
    final_fn = make_detector(best["code"])
    holdout_score = score(final_fn, holdout)
    base_holdout = score(base_fn, holdout)

    print("\n" + "=" * 60)
    print("FRESH-TEST RESULT (holdout the agents never saw)")
    print(f"  baseline F1 : {base_holdout.f1:.3f}")
    print(f"  final    F1 : {holdout_score.f1:.3f}")
    lift = holdout_score.f1 - base_holdout.f1
    print(f"  improvement : {lift:+.3f}  ({lift/ max(base_holdout.f1,1e-9)*100:+.0f}%)")
    print("=" * 60)

    path = store.save()
    print(f"\nfull evolution tree + lessons -> {path}  "
          f"({len(store.candidates)} candidates across {rounds} rounds)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--fake", action="store_const", dest="mode", const="fake")
    ap.add_argument("--real", action="store_const", dest="mode", const="real")
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--proposers", type=int, default=5)
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--hf", type=str, default=None, help="HF dataset name")
    ap.set_defaults(mode="fake")
    a = ap.parse_args()
    asyncio.run(run(a.mode, a.rounds, a.proposers, a.hf, a.k))
