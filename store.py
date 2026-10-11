"""
Persistence. Right now it's a JSON file; the document shape is deliberately
MongoDB-ready so Layer-3 is a drop-in swap (insert_one instead of list.append).

Each candidate detector is one document:
  {_id, round, proposer, strategy, parent_id, code, score:{...}, created_at}
Plus a 'lessons' list (the analyst's notes per round). The parent_id links let
you render the evolution TREE for the MongoDB "highest-aura" demo.

To swap to MongoDB:
    from pymongo import MongoClient
    col = MongoClient(URI)["arena"]["candidates"]
    col.insert_one(doc)            # instead of self.candidates.append(doc)
    col.find().sort("score.f1")    # instead of sorted(self.candidates, ...)
"""
import json, time, itertools
from pathlib import Path

_ids = itertools.count(1)


class Store:
    def __init__(self, path="run.json"):
        self.path = Path(path)
        self.candidates = []
        self.lessons = []

    def add_candidate(self, round, proposer, strategy, parent_id, code, score):
        doc = {
            "_id": next(_ids),
            "round": round,
            "proposer": proposer,
            "strategy": strategy,
            "parent_id": parent_id,
            "code": code,
            "score": score.as_dict(),
            "created_at": time.time(),
        }
        self.candidates.append(doc)
        return doc

    def add_lesson(self, round, text):
        self.lessons.append({"round": round, "text": text, "created_at": time.time()})

    def best(self, metric="f1"):
        return max(self.candidates, key=lambda d: d["score"][metric])

    def top_k(self, k, metric="f1"):
        return sorted(self.candidates, key=lambda d: d["score"][metric], reverse=True)[:k]

    def save(self):
        self.path.write_text(json.dumps(
            {"candidates": self.candidates, "lessons": self.lessons}, indent=2))
        return self.path
