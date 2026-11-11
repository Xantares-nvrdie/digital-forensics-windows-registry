"""Langkah 6 (modul): hitung TP/FP/FN(/TN) per parser dan per kategori, dan daftar error/unsupported.

Jalankan dari folder DF04_Kelompok4:
    .venv/bin/python 07_ANALYSIS/compute_confusion.py

Input : 07_ANALYSIS/registry_item_results.csv (hasil evaluate_artifacts.py)
Output: 07_ANALYSIS/confusion_counts.csv
        07_ANALYSIS/unsupported_error_cases.csv

Definisi "ditemukan benar" (6.1, mengikuti preregistration):
  * key_path harus match; bila expected value ada, value juga harus match -> TP.
  * Timestamp TIDAK ikut menentukan TP/FP/FN; dilaporkan sebagai metrik terpisah
    (kolom ts_match / ts_total).
  * Klasifikasi dibaca apa adanya dari registry_item_results.csv. Script ini tidak
    mengubah satu pun klasifikasi (6.3: FP tidak boleh diubah menjadi "error").

Precision = TP/(TP+FP), Recall = TP/(TP+FN), F1 = 2PR/(P+R); kosong bila penyebutnya 0.
TN dilaporkan tetapi tidak masuk rumus P/R/F1.
"""
import os

import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BASE, "07_ANALYSIS", "registry_item_results.csv")
OUT_COUNTS = os.path.join(BASE, "07_ANALYSIS", "confusion_counts.csv")
OUT_ERR = os.path.join(BASE, "07_ANALYSIS", "unsupported_error_cases.csv")
CATS = ["normal", "deleted", "corrupted", "manipulated"]


def ratio(n, d):
    return round(n / d, 4) if d else ""


def counts(g, tool, category):
    c = g["classification"].value_counts()
    tp, fp, fn, tn = (int(c.get(k, 0)) for k in ("TP", "FP", "FN", "TN"))
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p is not None and r is not None and p + r else None
    ts = g["timestamp_match"].astype(str)
    ts_total = int(ts.isin(["0", "0.0", "1", "1.0"]).sum())
    ts_match = int(ts.isin(["1", "1.0"]).sum())
    return {"tool": tool, "category": category, "n_artifacts": len(g), "tp": tp, "fp": fp,
            "fn": fn, "tn": tn,
            "precision": "" if p is None else round(p, 4),
            "recall": "" if r is None else round(r, 4),
            "f1": "" if f1 is None else round(f1, 4),
            "parser_error_rows": int((g["parser_error"].astype(str) != "-").sum()),
            "ts_match": ts_match, "ts_total": ts_total}


def issue_type(r):
    notes = str(r["notes"])
    if str(r["parser_error"]) != "-" and ("crash" in notes.lower() or "exception" in notes.lower()):
        return "parser_crash"
    if "U+FFFD" in notes:
        return "name_encoding_mangled"
    if r["classification"] == "FP" and r["category"] in ("normal", "deleted"):
        return "value_misread"
    if r["classification"] == "FP" and r["category"] == "manipulated":
        return "tampered_object_reported_active"
    if r["classification"] == "FN":
        return "object_not_extracted"
    return "other"


def main():
    d = pd.read_csv(SRC, dtype=str, keep_default_na=False)
    rows = []
    for tool, gt in d.groupby("tool"):
        for cat in CATS:
            rows.append(counts(gt[gt["category"] == cat], tool, cat))
        rows.append(counts(gt, tool, "ALL"))
    out = pd.DataFrame(rows)
    out.to_csv(OUT_COUNTS, index=False)
    print(out.to_string(index=False))

    # 6.3: daftar kasus error/unsupported (klasifikasi tidak diubah).
    # Semua baris dengan parser_error terisi, plus semua FP dan FN dan semua TN karena parser crash.
    mask = (d["parser_error"] != "-") | d["classification"].isin(["FP", "FN"])
    e = d[mask].copy()
    e["issue_type"] = e.apply(issue_type, axis=1)
    cols = ["artifact_id", "category", "hive_file", "tool", "classification", "issue_type",
            "parser_error", "notes"]
    e = e[cols].sort_values(["category", "artifact_id", "tool"])
    e.to_csv(OUT_ERR, index=False)
    print(f"\n{len(e)} error/unsupported rows -> {OUT_ERR}")
    print(e.groupby(["tool", "issue_type", "classification"]).size())


if __name__ == "__main__":
    main()
