"""Langkah 7.2-7.4: hash output, canonical comparison, ringkasan reproducibility.

Jalankan dari folder DF04_Kelompok4 setelah run_replications.py:
    .venv/bin/python 07_ANALYSIS/analyze_reproducibility.py

Output:
  06_RAW_RESULTS/output_json_sha256.txt      (format sha256sum, semua JSON di 04_ dan 05_ termasuk R1-R3)
  07_ANALYSIS/reproducibility_summary.csv    (per tool x hive)

Kriteria (7.3): identik per hash teks = byte sama. Identik kanonik = hasil parsing JSON sama
persis (urutan key objek tidak dipedulikan) -> 'canonical_same_order'; bila urutan record
juga diabaikan -> 'canonical_any_order'. Reproducible tidak disimpulkan dari hash teks saja.
"""
import glob
import hashlib
import json
import os
import statistics

import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGCSV = os.path.join(BASE, "06_RAW_RESULTS", "replication_run_log.csv")
SUFFIX = {"regipy": ("04_REGIPY_OUTPUT", "_regipy.json"),
          "python-registry": ("05_PYREG_OUTPUT", "_pyregistry.json")}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def load(path, tool):
    if tool == "regipy":
        return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    return json.load(open(path, encoding="utf-8"))


def canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def main():
    # 7.2 daftar hash seluruh output JSON (format sha256sum)
    files = sorted(glob.glob(os.path.join(BASE, "04_REGIPY_OUTPUT", "**", "*.json"), recursive=True)
                   + glob.glob(os.path.join(BASE, "05_PYREG_OUTPUT", "**", "*.json"), recursive=True))
    with open(os.path.join(BASE, "06_RAW_RESULTS", "output_json_sha256.txt"), "w", encoding="utf-8") as f:
        for p in files:
            f.write(f"{sha256(p)}  {os.path.relpath(p, BASE)}\n")
    print(f"{len(files)} JSON files hashed")

    log = pd.read_csv(LOGCSV, dtype={"output_sha256": str}, keep_default_na=False)
    rows = []
    for (tool, hive), g in log.groupby(["tool", "hive_file"], sort=False):
        d, suf = SUFFIX[tool]
        stem = hive.replace(".hive", "")
        original = os.path.join(BASE, d, stem + suf)  # R0: output Langkah 4-5
        g = g.sort_values("rep")
        runs = len(g)
        failed = int((g["status"] == "FAILED").sum())
        res = {"tool": tool, "category": g["category"].iloc[0], "hive_file": hive, "runs": runs,
               "failed_runs": failed,
               "input_hash_stable": int((g["input_matches_baseline"] == 1).all()),
               "runtime_median_sec": round(statistics.median(g["runtime_sec"]), 4),
               "runtime_min_sec": g["runtime_sec"].min(), "runtime_max_sec": g["runtime_sec"].max(),
               "error_count_per_run": ";".join(str(x) for x in g["error_count"])}
        if failed == runs:
            errs = set(g["parser_error"])
            res.update(identical_hash="NA", canonical_same_order="NA", canonical_any_order="NA",
                       matches_original_canonical="NA", outcome="consistent_failure" if len(errs) == 1
                       else "inconsistent_failure", parser_error=sorted(errs)[0])
        elif failed:
            res.update(identical_hash="NA", canonical_same_order="NA", canonical_any_order="NA",
                       matches_original_canonical="NA", outcome="MIXED_SUCCESS_AND_FAILURE",
                       parser_error="; ".join(sorted(set(g["parser_error"]) - {"-"})))
        else:
            hashes = list(g["output_sha256"])
            objs = [load(os.path.join(BASE, p), tool) for p in g["output_file"]]
            same_hash = len(set(hashes)) == 1
            same_order = len({canon(o) for o in objs}) == 1
            any_order = len({canon(sorted(canon(r) for r in o)) for o in objs}) == 1
            orig_ok = ""
            if os.path.exists(original):
                orig_ok = int(canon(load(original, tool)) == canon(objs[0]))
            else:
                orig_ok = "NA"
            res.update(identical_hash=int(same_hash), canonical_same_order=int(same_order),
                       canonical_any_order=int(any_order), matches_original_canonical=orig_ok,
                       outcome="reproducible" if same_order else
                       ("reproducible_order_differs" if any_order else "NOT_REPRODUCIBLE"),
                       parser_error="-")
        rows.append(res)
    out = pd.DataFrame(rows)
    out.to_csv(os.path.join(BASE, "07_ANALYSIS", "reproducibility_summary.csv"), index=False)
    print(out[["tool", "hive_file", "failed_runs", "identical_hash", "canonical_same_order",
               "canonical_any_order", "matches_original_canonical", "outcome",
               "runtime_median_sec"]].to_string(index=False))

    ok = out[out["identical_hash"] != "NA"]
    print("\nReproducibility rate (hash teks identik) per tool:")
    for tool, g in out.groupby("tool"):
        total_runs = int(g["runs"].sum())
        ident_runs = int(g.loc[g["outcome"].isin(["reproducible"]), "runs"].sum()
                         + g.loc[g["outcome"] == "consistent_failure", "runs"].sum())
        print(f"  {tool}: {ident_runs}/{total_runs} run identik (termasuk kegagalan konsisten)")
    print("input hash stabil di semua run:", bool((log["input_matches_baseline"] == 1).all()))


if __name__ == "__main__":
    main()

