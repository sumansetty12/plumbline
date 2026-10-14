"""Run the simulated scenarios and write eval/RESULTS.md.

    python -m eval.run_eval --seed 7 --per-scenario 12
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.scenarios import SCENARIOS  # noqa: E402


def run(seed: int, per: int) -> dict:
    rng = random.Random(seed)
    rows = []
    for sc in SCENARIOS:
        for i in range(per):
            res = sc.run(random.Random(rng.randrange(2 ** 32)))
            actual = res.alerts
            correct = sc.required <= actual and actual <= (sc.required | sc.allowed_extra)
            rows.append({"scenario": sc.name, "category": sc.category, "harmful": sc.harmful,
                         "required": sorted(sc.required), "actual": sorted(actual),
                         "correct": correct, "any_alert": bool(actual)})
    return summarize(rows, seed, per)


def pct(n, d):
    return "n/a" if d == 0 else f"{100 * n / d:.1f}%"


def summarize(rows, seed, per):
    by = defaultdict(list)
    for r in rows:
        by[r["scenario"]].append(r)
    benign = [r for r in rows if r["category"] == "benign"]
    designed = [r for r in rows if r["category"] == "designed"]
    hard = [r for r in rows if r["category"] == "known-hard"]
    return {
        "seed": seed, "per_scenario": per, "total": len(rows),
        "benign_false_alarm_rate": pct(sum(r["any_alert"] for r in benign), len(benign)),
        "designed_correct": pct(sum(r["correct"] for r in designed), len(designed)),
        "known_hard_harm_detected": pct(sum(r["any_alert"] for r in hard), len(hard)),
        "harmful_overall_detected": pct(sum(r["any_alert"] for r in rows if r["harmful"]),
                                        sum(r["harmful"] for r in rows)),
        "per_scenario_table": [
            {"scenario": name, "category": rs[0]["category"], "runs": len(rs),
             "correct": sum(r["correct"] for r in rs),
             "alerted": sum(r["any_alert"] for r in rs),
             "harmful_missed": sum(r["harmful"] and not r["any_alert"] for r in rs)}
            for name, rs in by.items()],
    }


def markdown(s: dict) -> str:
    lines = [
        "# Plumbline evaluation results (SIMULATED data)", "",
        f"Seed `{s['seed']}`, {s['per_scenario']} runs per scenario, {s['total']} scenarios in total.", "",
        "> **Read this first.** Every scenario here is simulated, and the scenarios were written by the same people who wrote",
        "> the rules. The designed-for results show the implementation behaves as intended and will catch regressions. They are",
        "> **not** a measure of detection against real attackers. The known-hard rows are cases the rules deliberately do not cover.", "",
        "| Measure | Result |", "|---|---|",
        f"| False alarms on benign scenarios | {s['benign_false_alarm_rate']} |",
        f"| Designed-for scenarios handled exactly as expected | {s['designed_correct']} |",
        f"| Known-hard harmful scenarios that raised any alert | {s['known_hard_harm_detected']} |",
        f"| All harmful scenarios that raised any alert | {s['harmful_overall_detected']} |", "",
        "## By scenario", "", "| Scenario | Category | Runs | Matched design | Raised an alert | Harmful but missed |", "|---|---|---|---|---|---|",
    ]
    for r in s["per_scenario_table"]:
        lines.append(f"| {r['scenario']} | {r['category']} | {r['runs']} | {r['correct']} | {r['alerted']} | {r['harmful_missed']} |")
    lines += ["", "## What the known-hard rows mean", "",
              "- **slow_exfiltration_within_scope**: a contractor reads a large amount of data they are allowed to read. No rule counts volume.",
              "- **reads_unrelated_to_purpose**: allowed reads that do not match the stated purpose. Purpose is free text, so the rules cannot judge it.",
              "- **credentials_used_from_two_places**: one session used from two IP addresses. The rules do not compare source addresses.", "",
              "These gaps are what the anomaly-detection layer (feature M1.8) is meant to address. Until it is built and measured,",
              "do not claim Plumbline detects them.", ""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--per-scenario", type=int, default=12)
    ap.add_argument("--out", default=str(Path(__file__).parent / "RESULTS.md"))
    a = ap.parse_args()
    s = run(a.seed, a.per_scenario)
    Path(a.out).write_text(markdown(s))
    print(json.dumps({k: v for k, v in s.items() if k != "per_scenario_table"}, indent=2))


if __name__ == "__main__":
    main()
