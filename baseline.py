"""
The starting line. Deliberately naive so the improvement curve has somewhere
to go. This is the number every round is measured against (the 40% criterion).

A dumb keyword blocklist: catches the obvious "ignore previous instructions"
attacks, misses anything cleverly worded, and will false-positive on a benign
message that happens to say "ignore". That gap is the whole point.
"""

BASELINE_CODE = '''
def detect(text):
    bad = ["ignore previous", "ignore all previous", "developer mode",
           "system override", "reveal", "secret code", "disregard"]
    t = text.lower()
    return any(b in t for b in bad)
'''


def detect(text):
    bad = ["ignore previous", "ignore all previous", "developer mode",
           "system override", "reveal", "secret code", "disregard"]
    t = text.lower()
    return any(b in t for b in bad)
