from __future__ import annotations

import re
import statistics
from pathlib import Path

LISTS = ("positive", "negative", "uncertainty", "litigious")
SHIFT_SD = 1.5
BASELINE_RELEASES = 8
MIN_BASELINE = 4
_WORD_RE = re.compile(r"[a-z]+(?:-[a-z]+)*")


class Lexicon:
    def __init__(self, folder: Path):
        self.words: dict[str, frozenset[str]] = {}
        for name in LISTS:
            path = Path(folder) / f"{name}.txt"
            lines = path.read_text(encoding="utf-8").split("\n") if path.is_file() else []
            self.words[name] = frozenset(w.strip() for w in lines if w.strip() and not w.startswith("#"))

    def score(self, text: str) -> dict:
        tokens = _WORD_RE.findall((text or "").lower())
        n = len(tokens)
        counts = {name: sum(1 for t in tokens if t in self.words[name]) for name in LISTS}
        return {
            "words": n,
            "positive": counts["positive"], "negative": counts["negative"],
            "tone": round((counts["positive"] - counts["negative"]) / (counts["positive"] + counts["negative"] + 1), 4),
            "uncertainty": round(1000 * counts["uncertainty"] / n, 2) if n else 0.0,
            "litigious": round(1000 * counts["litigious"] / n, 2) if n else 0.0,
        }


def shift(current: float, prior: list[float]) -> dict | None:
    baseline = prior[-BASELINE_RELEASES:]
    if len(baseline) < MIN_BASELINE:
        return None
    sd = statistics.stdev(baseline)
    if sd <= 0:
        return None
    z = (current - statistics.fmean(baseline)) / sd
    if abs(z) < SHIFT_SD:
        return None
    return {"z": round(z, 3), "baseline_mean": round(statistics.fmean(baseline), 4), "baseline_n": len(baseline),
            "direction": "more positive" if z > 0 else "more negative"}
