"""Acceptance checks for src/incidents.py. Run with `python tests/test_incidents.py` or `pytest tests`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd

from src.detector import run_detector
from src.features import build_features, feature_sets
from src.incidents import group_alerts, incident_metrics
from src.prepare import load_raw, prepare


def _scored(rows):
    """rows: (ts, client, parent, y, alert); every row is a test row."""
    return pd.DataFrame(rows, columns=["ts", "client", "parent", "y", "alert"]).assign(role="test", score=0.5)


def test_alerts_close_in_time_form_one_incident_and_far_apart_form_two():
    s = _scored([(0, "a", "x.com", 0, 1), (30, "a", "x.com", 0, 1), (89, "a", "x.com", 0, 1),
                 (400, "a", "x.com", 0, 1)])
    inc = group_alerts(s)
    assert list(inc["alerts"]) == [3, 1]


def test_different_client_or_domain_is_a_different_incident():
    s = _scored([(0, "a", "x.com", 0, 1), (1, "b", "x.com", 0, 1), (2, "a", "y.com", 0, 1)])
    assert len(group_alerts(s)) == 3


def test_only_alerts_on_test_rows_count():
    s = _scored([(0, "a", "x.com", 0, 1), (1, "a", "x.com", 0, 0)])
    s.loc[0, "role"] = "fit"
    assert len(group_alerts(s)) == 0


def test_tunnel_flag_and_time_to_first_alert():
    s = _scored([(100, "t", "pirate.sea", 1, 0), (101, "t", "pirate.sea", 1, 0), (103, "t", "pirate.sea", 1, 1),
                 (104, "t", "pirate.sea", 1, 1), (500, "a", "x.com", 0, 1), (3700, "a", "x.com", 0, 0)])
    m = incident_metrics(s)
    assert m["tunnel_incidents"] == 1 and m["false_incidents"] == 1 and m["incidents"] == 2
    assert m["seconds_to_first_alert"] == 3
    assert abs(m["false_incidents_per_hour"] - 1 / ((3700 - 100) / 3600)) < 1e-9


def test_missed_tunnel_gives_nan():
    s = _scored([(100, "t", "pirate.sea", 1, 0), (200, "a", "x.com", 0, 0)])
    m = incident_metrics(s)
    assert np.isnan(m["seconds_to_first_alert"]) and m["incidents"] == 0


def test_real_run_has_one_tunnel_incident_and_fewer_incidents_than_alerts():
    m = build_features(prepare(load_raw(), session="second"), window_s=60)
    scored, _ = run_detector(m, feature_sets(60)["forced"])
    im = incident_metrics(scored)
    test = scored[scored.role == "test"]
    assert im["tunnel_incidents"] == 1
    assert im["incidents"] < int(test["alert"].sum())


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {name}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
