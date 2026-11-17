"""Group a detector's alerts into incidents, the unit an analyst works with.

A tunnel session produces hundreds of alert queries, and a busy normal domain produces dozens. Counting alert
queries makes the false positives look large; grouping them per client and parent domain (alerts less than
`gap` seconds apart form one incident) shows how many separate things an analyst would have to look at.

    from src.incidents import group_alerts, incident_metrics
    incidents = group_alerts(scored)        # one row per incident
    incident_metrics(scored)                # false incidents, per hour, time to first alert

Works on the `scored` table of any model (run_detector, run_rule): it needs the columns role, alert, client,
parent, ts, y and score, and only looks at the test rows.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

GAP_S = 60.0
COLUMNS = ["client", "parent", "start", "end", "alerts", "top_score", "is_tunnel"]


def group_alerts(scored: pd.DataFrame, gap: float = GAP_S) -> pd.DataFrame:
    """One row per incident among the test rows: alerts of one (client, parent domain) pair with gaps of at most
    `gap` seconds. `is_tunnel` is True when the incident contains a tunnel query (label used for evaluation only)."""
    t = scored[(scored["role"] == "test") & (scored["alert"] == 1)].sort_values("ts", kind="mergesort")
    rows = []
    for (client, parent), g in t.groupby(["client", "parent"], sort=False):
        ts, y, score = g["ts"].to_numpy(), g["y"].to_numpy(), g["score"].to_numpy()
        start = 0
        for i in range(1, len(g) + 1):
            if i == len(g) or ts[i] - ts[i - 1] > gap:
                rows.append({"client": client, "parent": parent, "start": ts[start], "end": ts[i - 1],
                             "alerts": i - start, "top_score": float(score[start:i].max()),
                             "is_tunnel": bool(y[start:i].max())})
                start = i
    out = pd.DataFrame(rows, columns=COLUMNS)
    return out.sort_values("start", kind="mergesort").reset_index(drop=True)


def incident_metrics(scored: pd.DataFrame, gap: float = GAP_S) -> dict:
    """incidents, false_incidents, tunnel_incidents, false_incidents_per_hour (of test traffic) and
    seconds_to_first_alert (from the first tunnel query to the first alert on a tunnel query; NaN if missed)."""
    inc = group_alerts(scored, gap)
    test = scored[scored["role"] == "test"]
    hours = max((test["ts"].max() - test["ts"].min()) / 3600.0, 1e-9)
    is_tunnel = inc["is_tunnel"].astype(bool)
    tunnel = test[test["y"] == 1]
    hits = tunnel[tunnel["alert"] == 1]
    first = float(hits["ts"].min() - tunnel["ts"].min()) if len(hits) else float("nan")
    false = int((~is_tunnel).sum())
    return {"incidents": len(inc), "false_incidents": false, "tunnel_incidents": int(is_tunnel.sum()),
            "false_incidents_per_hour": false / hours, "seconds_to_first_alert": first}
