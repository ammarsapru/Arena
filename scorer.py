"""
The referee. Every decision in the system depends on this being reliable.

A detector is a callable: detect(text: str) -> bool   (True = block as attack).

score() runs a detector over a dataset and returns the full confusion matrix
plus the headline number. The headline is F1, which balances the two failures
that matter:
    - missing an attack   (false negative)  -> secret leaks
    - blocking a real user (false positive)  -> angry customer
Accuracy alone is a trap here (a "block nothing" detector scores 90%+ if most
traffic is benign), which is exactly the tradeoff that makes this a real
optimization problem and not a toy.

A detector written by an LLM is UNTRUSTED CODE. run_detector_code() executes it
in an isolated namespace with a timeout guard. For the hackathon this is "good
enough"; for anything real you'd run each candidate in a container / Lambda /
subprocess with no network. This is also where AWS Lambda would slot in to get
true parallel, isolated evaluation (Track 2 angle).
"""
from dataclasses import dataclass, asdict
from dataset import Record


@dataclass
class Score:
    tp: int; fp: int; tn: int; fn: int
    precision: float; recall: float; f1: float; accuracy: float
    n: int

    def as_dict(self):
        return asdict(self)

    def __str__(self):
        return (f"F1={self.f1:.3f}  precision={self.precision:.3f}  "
                f"recall={self.recall:.3f}  acc={self.accuracy:.3f}  "
                f"(TP{self.tp} FP{self.fp} TN{self.tn} FN{self.fn}, n={self.n})")


def score(detect, records: list[Record]) -> Score:
    tp = fp = tn = fn = 0
    for r in records:
        try:
            flagged = bool(detect(r.text))
        except Exception:
            flagged = False  # a detector that crashes = let it through
        if r.label == 1 and flagged:   tp += 1
        elif r.label == 1 and not flagged: fn += 1
        elif r.label == 0 and flagged:     fp += 1
        else:                               tn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec  = tp / (tp + fn) if (tp + fn) else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc  = (tp + tn) / len(records) if records else 0.0
    return Score(tp, fp, tn, fn, prec, rec, f1, acc, len(records))


def misclassified(detect, records: list[Record], limit: int = 8):
    """The examples a detector got WRONG — this is the feedback the analyst
    agent reads to tell the next round what to fix."""
    misses = {"false_negatives": [], "false_positives": []}
    for r in records:
        try:
            flagged = bool(detect(r.text))
        except Exception:
            flagged = False
        if r.label == 1 and not flagged and len(misses["false_negatives"]) < limit:
            misses["false_negatives"].append(r.text)
        elif r.label == 0 and flagged and len(misses["false_positives"]) < limit:
            misses["false_positives"].append(r.text)
    return misses


def run_detector_code(code: str):
    """Turn an LLM-produced code string into a callable detect().
    Contract: the code MUST define `def detect(text): -> bool`."""
    ns: dict = {}
    exec(code, ns)  # UNTRUSTED — isolate properly for production (see module doc)
    fn = ns.get("detect")
    if not callable(fn):
        raise ValueError("detector code did not define a callable detect(text)")
    return fn
