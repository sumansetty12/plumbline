# Plumbline evaluation results (SIMULATED data)

Seed `7`, 12 runs per scenario, 264 scenarios in total.

> **Read this first.** Every scenario here is simulated, and the scenarios were written by the same people who wrote
> the rules. The designed-for results show the implementation behaves as intended and will catch regressions. They are
> **not** a measure of detection against real attackers. The known-hard rows are cases the rules deliberately do not cover.

| Measure | Result |
|---|---|
| False alarms on benign scenarios | 0.0% |
| Designed-for scenarios handled exactly as expected | 100.0% |
| Known-hard harmful scenarios that raised any alert | 0.0% |
| All harmful scenarios that raised any alert | 81.2% |

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
| volume_spike_vs_baseline | designed | 12 | 12 | 12 | 0 |
| credentials_used_from_two_places | designed | 12 | 12 | 12 | 0 |
| new_ip_and_new_actions_and_odd_hour | designed | 12 | 12 | 12 | 0 |
| benign_with_history | benign | 12 | 12 | 0 | 0 |
| benign_busier_day | benign | 12 | 12 | 0 | 0 |
| benign_new_ip_only | benign | 12 | 12 | 0 | 0 |
| exfiltration_without_baseline | known-hard | 12 | 12 | 0 | 12 |
| low_and_slow_inside_baseline | known-hard | 12 | 12 | 0 | 12 |
| reads_unrelated_to_purpose | known-hard | 12 | 12 | 0 | 12 |

## What the known-hard rows mean

- **exfiltration_without_baseline**: a brand-new contractor reads a lot of data they are allowed to read. With no earlier sessions there is nothing to compare against.
- **low_and_slow_inside_baseline**: an attacker who behaves exactly like the contractor's normal day (same volume, address and hours). Baseline comparison cannot see this.
- **reads_unrelated_to_purpose**: allowed reads that do not match the stated purpose. Purpose is free text; only the optional AI explanation looks at it, and it is not part of this simulation.

## Caveats about the anomaly rows

- The anomaly thresholds (3.5 robust z-score, 4x the usual volume, signal weights) were set by the same people who wrote the scenarios, and one threshold (the volume ratio) was raised after a first run produced false alarms on a busy-day scenario. The results show the detector does what it was designed to do, not how it would perform on real contractors.
- The Isolation Forest only runs when a contractor has at least 20 earlier sessions, and flags a session only if it scores as more unusual than every earlier session.
- Earlier sessions are assumed to be legitimate. A contractor who was already misbehaving teaches the baseline to accept it.
