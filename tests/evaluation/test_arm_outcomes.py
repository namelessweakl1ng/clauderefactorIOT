"""Per-arm attacker-success scoring for the RL evidence report."""

from evaluation.arm_outcomes import score_run, summarise


def run(eid, scenario, kind, result, events):
    return score_run({"experiment_id": eid, "scenario_id": scenario, "trial_kind": kind, "result": result}, events)


LOGIN_OK = {"event": {"category": "authentication", "outcome": "success"}}
LOGIN_DENIED = {"event": {"category": "authentication", "outcome": "failure"}, "hardening": {"actions": ["deny_auth"], "decision_id": "HRD-1"}}


def test_success_hardening_and_controls_are_scored_separately():
    runs = [
        run("E1", "dvr", "attack", "TP", [LOGIN_OK]),
        run("E2", "dvr", "attack", "TP", [LOGIN_DENIED]),
        run("E3", "ctl", "control", "TN", [LOGIN_OK]),  # a control's login is not attacker success
        run("E4", "dvr", "attack", "INCONCLUSIVE", []),  # no telemetry: unscorable, excluded
    ]
    summary = summarise(runs)
    assert summary["attack_runs_scored"] == 2 and summary["attacker_success"] == 1
    assert summary["hardened_attack_runs"] == 1 and summary["effects_seen"] == ["deny_auth"]
    assert summary["controls_with_harm"] == 1 and summary["per_scenario"]["dvr"] == {"runs": 2, "attacker_succeeded": 1, "hardened": 1}
    assert summary["attacker_success_ci95"][0] < 0.5 < summary["attacker_success_ci95"][1]


def test_hardened_run_that_made_the_attack_fail_is_still_scored():
    """RUNNER_FAILED -> INCONCLUSIVE detection result, but it is the defence working."""
    summary = summarise([run("E1", "dvr", "attack", "INCONCLUSIVE", [LOGIN_DENIED])])
    assert summary["attack_runs_scored"] == 1 and summary["attacker_success"] == 0 and summary["hardened_attack_runs"] == 1
