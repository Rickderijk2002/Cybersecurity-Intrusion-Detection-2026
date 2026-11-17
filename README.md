# Cybersecurity Intrusion Detection (JM2030)

Group final project: find the malicious traffic in a PCAP with a data science technique, then write a threat report and present it.

- **Due:** 5 Dec 2026, 23:59 (upload as one zip). **Presentation:** 30 Nov or 1 Dec
- **Case:** Case 1, DNS tunnelling (see `docs/Case and technique.md`)
- **Technique:** Isolation Forest
- **Start here (modelling):** `docs/phase2 - feature engineering overview.md`, then `docs/data_dictionary.md`, `notebooks/03_features.ipynb` and the detector handoff `docs/tmp/handoff-2026-11-15-1945.md`
- **Brief and grading criteria:** `assignment/Assignment brief.md`

## Layout

| Path | What lives there |
|---|---|
| `assignment/` | The Canvas brief and rubric, copied verbatim |
| `data/raw/` | PCAP and `dns.log`. **Git-ignored**, download from Canvas |
| `src/` | Python modules: data preparation (`prepare.py`), features (`features.py`), stress-test variants (`variants.py`), the Isolation Forest detector (`detector.py`), evaluation helpers (`evaluation.py`), rule baselines (`baselines.py`), incident grouping (`incidents.py`) and explanatory figures (`plots.py`) |
| `notebooks/` | Exploration (01 to 03) and the results notebook (`04_results.ipynb`: main result, rule baselines, incidents, alert line and window, stress tests, errors). Figures are in `notebooks/figures/` |
| `slides/` | Presentation (20 min plus 5 min questions) |
| `docs/` | Working notes: case and technique choice, task division, investigation log, the modelling handoff and data dictionary, and the newest handoffs in `docs/tmp/` |

## Run the pipeline

```bash
python main.py --all --tests     # features (default + strict variant) and the feature tests
python -m src.detector           # Isolation Forest, writes data/processed/scores.csv; add --checks for the model checks
python tests/test_detector.py    # detector and evaluation tests
python tests/test_plots.py       # figure tests
python tests/test_incidents.py   # incident grouping tests
python tests/test_baselines.py   # rule baseline tests
python -m src.plots              # writes notebooks/figures/isolation_forest_view.png
```

`data/processed/` is git-ignored, so run `python main.py` first. It needs `data/raw/dns.log` from Canvas.

## The report

Written in **Overleaf** by the whole group (decided 2026-11-07). The Overleaf project can be opened in VS Code with the Overleaf Workshop extension. The report is not stored in this repo; the Quarto draft and the Canvas template that used to be in `report/` were removed on 2026-11-09.

## Python setup

```bash
uv venv
uv pip install -r requirements.txt
```

## Submission zip

Report PDF, slides (PPTX or PDF), and the code or notebook. Raw PCAPs are not part of the zip.

## Team workflow

- Work on a branch per person or per section, open a pull request, one other person reads before merge.
- Commit notebooks with outputs cleared (`jupyter nbconvert --clear-output --inplace`), so diffs stay readable.
- Never commit the PCAP or `dns.log`.
