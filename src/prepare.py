"""Load dns.log, attach the labels and derive the columns every later step needs.

Usage:
    from src.prepare import load_raw, prepare
    raw = load_raw()                      # 3,645 rows, labels joined, file order
    prep = prepare(raw, session="second") # primary run: burst 2 only, cut at 18:30 UTC

"""
from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd
import tldextract

ROOT = Path(__file__).resolve().parents[1]

# The two tunnel bursts are 46 minutes apart; anything between them separates burst 1 from burst 2.
BURST_SPLIT = pd.Timestamp("2023-01-07 18:30:00")

# Default train/test cut (UTC) per session. Train = rows before the cut, test = rows from the cut on.
DEFAULT_CUT = {
    "second": pd.Timestamp("2023-01-07 18:30:00"),  # primary: train = benign before 18:30, test holds burst 2
    "first": pd.Timestamp("2023-01-07 18:04:36"),   # strict variant: train = the quiet start, test holds burst 1
    "both": pd.Timestamp("2023-01-07 18:30:00"),    # appendix only: train then contains burst 1
}

# First character of a tunnel query name = iodine command (report Table 2.3, 01_discovery section 10).
# Used only to label the phase for error analysis, never as a feature.
# `n` (set fragment size) is one short query that applies the result of the probing, so it counts as
# set-up with v and l; only the 13 long `r` queries are size probes. This reproduces the report's counts:
# 173 pings, 24 data, 13 size probes and 12 set-up queries (handshake 3 + encoding_test 9).
PHASE_BY_PREFIX = {
    "v": "handshake", "l": "handshake", "n": "handshake",
    "y": "encoding_test", "z": "encoding_test", "s": "encoding_test", "o": "encoding_test",
    "r": "size_probe",
    "p": "ping",
    "1": "data",
}

_ESCAPE = re.compile(r"\\x([0-9A-Fa-f]{2})")
# Offline suffix list snapshot, no cache directory writes. ICANN suffixes only (no private PSL entries).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def _find_raw_dir() -> Path:
    raw = ROOT / "data" / "raw"
    return raw if (raw / "dns.log").exists() else raw / "Case 1"  # Canvas download keeps a "Case 1" folder


def to_wire_bytes(query: str) -> bytes:
    """Turn Zeek's \\xNN escapes back into single bytes. The file is read as latin-1, so every
    other character is already one byte."""
    return _ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), query).encode("latin-1")


def load_raw(raw_dir: Path | None = None, labels_path: Path | None = None) -> pd.DataFrame:
    """Read dns.log (columns from the #fields line) and join data/labels.csv on row_id.

    Returns one row per log row in FILE ORDER (not sorted). Adds `row_id`, `dt` (UTC), `label`.
    """
    raw_dir = raw_dir or _find_raw_dir()
    labels_path = labels_path or ROOT / "data" / "labels.csv"
    log = raw_dir / "dns.log"

    with open(log, encoding="latin-1") as f:
        cols = next(line for line in f if line.startswith("#fields")).rstrip("\n").split("\t")[1:]
    df = pd.read_csv(log, sep="\t", comment="#", names=cols, na_values=["-"],
                     keep_default_na=False, encoding="latin-1")
    df.index.name = "row_id"
    # join BEFORE any sorting
    df = df.join(pd.read_csv(labels_path, index_col="row_id"))
    if df["label"].isna().any() or df["query"].isna().any():
        raise ValueError("missing labels or query names after the join")
    df = df.reset_index()
    df["dt"] = pd.to_datetime(df["ts"], unit="s")  # naive, UTC
    return df


def _parent_of(wire_name: bytes) -> str:
    """Registered domain (public suffix list), lower-cased. Falls back to the last two labels for names
    the list does not know (pirate.sea, internal names, bare hosts)."""
    name = wire_name.decode("latin-1").rstrip(".")
    registered = _EXTRACT(name).top_domain_under_public_suffix
    if registered:
        return registered.lower()
    labels = name.lower().split(".")
    return ".".join(labels[-2:])


def derive_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Add name_bytes, name, labels_bytes, parent, subdomain, y, burst, is_replay, phase."""
    df = df.copy()
    wire = df["query"].map(to_wire_bytes)
    df["name"] = wire.map(lambda b: b.decode("latin-1"))        # exact name, one character per wire byte
    df["name_bytes"] = wire.map(len)
    df["labels_bytes"] = wire.map(lambda b: b.rstrip(b".").split(b"."))

    # tldextract once per distinct name
    parents = {b: _parent_of(b) for b in set(wire)}
    df["parent"] = wire.map(parents)

    def _subdomain(labels: list[bytes], parent: str) -> str:
        n = parent.count(".") + 1
        return b".".join(labels[:-n]).decode("latin-1")
    df["subdomain"] = [_subdomain(l, p) for l, p in zip(df["labels_bytes"], df["parent"])]

    df["y"] = (df["label"] == "tunnel").astype(int)
    is_tunnel = df["y"] == 1
    df["burst"] = np.where(~is_tunnel, 0, np.where(df["dt"] < BURST_SPLIT, 1, 2))
    df["is_replay"] = df["burst"] == 2

    prefix = df["subdomain"].str[:1]
    phase = prefix.map(PHASE_BY_PREFIX)
    df["phase"] = np.where(is_tunnel, phase, "benign")
    unknown = df[is_tunnel & phase.isna()]
    if len(unknown):
        raise ValueError(f"{len(unknown)} tunnel rows have an unknown first character: "
                         f"{sorted(set(unknown['subdomain'].str[:1]))}")
    return df


def prepare(df: pd.DataFrame, session: str = "second", cut: str | pd.Timestamp | None = None) -> pd.DataFrame:
    """Derive columns, keep one tunnel session, sort by time and mark the train/test split.

    session: "second" (primary), "first" (strict variant) or "both" (appendix only).
    The burst that is not kept is removed from the whole stream, not only from training, so it cannot
    distort any later window or "never repeated a name" feature.
    cut: train = ts < cut, test = ts >= cut. Defaults per session, see DEFAULT_CUT.
    """
    if session not in DEFAULT_CUT:
        raise ValueError(f"session must be one of {list(DEFAULT_CUT)}")
    cut = pd.Timestamp(cut) if cut is not None else DEFAULT_CUT[session]

    d = derive_columns(df)
    if session == "first":
        d = d[d["burst"] != 2]
    elif session == "second":
        d = d[d["burst"] != 1]

    d = d.sort_values("ts", kind="mergesort").reset_index(drop=True)  # stable, AFTER the join
    d["split"] = np.where(d["dt"] < cut, "train", "test")

    keep = ["row_id", "ts", "dt", "split", "label", "y", "burst", "is_replay", "phase",
            "client", "query", "name", "name_bytes", "labels_bytes", "parent", "subdomain",
            "qtype", "qtype_name", "rcode_name"]
    d = d.rename(columns={"id.orig_h": "client"})
    return d[keep]


PROCESSED = ROOT / "data" / "processed"


def prepared_path(session: str = "second") -> Path:
    """Default run (second) is prepared.csv; other sessions get their name in the file."""
    return PROCESSED / ("prepared.csv" if session == "second" else f"prepared_{session}.csv")


def write_prepared(prep: pd.DataFrame, session: str = "second") -> Path:
    """Write the prepared table to CSV so it can be inspected in a spreadsheet or editor.
    `labels_bytes` (a list of byte strings per row) is left out: the file is for looking, not for reading back."""
    path = prepared_path(session)
    path.parent.mkdir(parents=True, exist_ok=True)
    prep.drop(columns=["labels_bytes"]).to_csv(path, index=False, encoding="utf-8")
    return path


if __name__ == "__main__":
    raw = load_raw()
    for s in ("second", "first", "both"):
        p = prepare(raw, session=s)
        print(f"session={s}: {len(p)} rows, tunnel {int(p['y'].sum())}")
        print(p.groupby(["split", "label"]).size().unstack(fill_value=0), "\n")
