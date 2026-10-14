# Plumbline evaluation results (SIMULATED data)

Seed `7`, 12 runs per scenario, 192 scenarios in total.

> **Read this first.** Every scenario here is simulated, and the scenarios were written by the same people who wrote
> the rules. The designed-for results show the implementation behaves as intended and will catch regressions. They are
> **not** a measure of detection against real attackers. The known-hard rows are cases the rules deliberately do not cover.

| Measure | Result |
|---|---|
| False alarms on benign scenarios | 0.0% |
| Designed-for scenarios handled exactly as expected | 100.0% |
| Known-hard harmful scenarios that raised any alert | 0.0% |
| All harmful scenarios that raised any alert | 76.9% |

## By scenario

| Scenario | Category | Runs | Matched design | Raised an alert | Harmful but missed |
|---|---|---|---|---|---|
| benign_session | benign | 12 | 12 | 0 | 0 |
| benign_healthy_principal | benign | 12 | 12 | 0 | 0 |
| benign_new_unused_principal | benign | 12 | 12 | 0 | 0 |
| scope_creep | designed | 12 | 12 | 12 | 0 |
| destructive_in_scope | designed | 12 | 12 | 12 | 0 |
| stolen_credentials | designed | 12 | 12 | 12 | 0 |
| use_after_revocation | designed | 12 | 12 | 12 | 0 |
| use_after_expiry | designed | 12 | 12 | 12 | 0 |
| forgotten_account | designed | 12 | 12 | 12 | 0 |
| untagged_principal | designed | 12 | 12 | 12 | 0 |
| unknown_contract | designed | 12 | 12 | 12 | 0 |
| dormant_principal | designed | 12 | 12 | 12 | 0 |
| over_broad_request | designed | 12 | 12 | 12 | 0 |
| slow_exfiltration_within_scope | known-hard | 12 | 12 | 0 | 12 |
| reads_unrelated_to_purpose | known-hard | 12 | 12 | 0 | 12 |
| credentials_used_from_two_places | known-hard | 12 | 12 | 0 | 12 |

## What the known-hard rows mean

- **slow_exfiltration_within_scope**: a contractor reads a large amount of data they are allowed to read. No rule counts volume.
- **reads_unrelated_to_purpose**: allowed reads that do not match the stated purpose. Purpose is free text, so the rules cannot judge it.
- **credentials_used_from_two_places**: one session used from two IP addresses. The rules do not compare source addresses.

These gaps are what the anomaly-detection layer (feature M1.8) is meant to address. Until it is built and measured,
do not claim Plumbline detects them.
