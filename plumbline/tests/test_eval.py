"""The evaluation harness doubles as a regression test for the rules."""
from eval.run_eval import run


def test_designed_cases_benign_cases_and_known_gaps():
    s = run(seed=3, per=3)
    assert s["benign_false_alarm_rate"] == "0.0%"
    assert s["designed_correct"] == "100.0%"
    # Known gaps stay documented: if a rule starts catching one of these, update the
    # README and eval/RESULTS.md so the claims stay honest.
    assert s["known_hard_harm_detected"] == "0.0%"


def test_results_are_reproducible_for_a_seed():
    assert run(seed=11, per=2) == run(seed=11, per=2)
