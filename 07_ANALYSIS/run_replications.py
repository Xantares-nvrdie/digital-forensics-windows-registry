"""Langkah 7 (modul): ulangi extraction 3x (R1/R2/R3) untuk uji stabilitas.

Jalankan dari folder DF04_Kelompok4:
    .venv/bin/python 07_ANALYSIS/run_replications.py

Untuk setiap run (R1..R3), tiap tool (regipy, python-registry), tiap hive (11 hive):
  * hitung SHA-256 hive working copy sebelum dan sesudah run, serta bandingkan dengan baseline
  * jalankan parser, ukur runtime (wall-clock, dari start proses sampai selesai)
  * simpan output di 04_REGIPY_OUTPUT/R{n}/ dan 05_PYREG_OUTPUT/R{n}/
  * simpan stdout/stderr (termasuk traceback run yang gagal) di 06_RAW_RESULTS/R{n}/
Hasil: 06_RAW_RESULTS/replication_run_log.csv. Run yang gagal tetap dicatat.
Output awal di folder induk (hasil Langkah 4-5) tidak disentuh dan ikut dibandingkan sebagai "R0".
"""
import csv
import hashlib
import json
import os
import subprocess
import sys
import time

import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(BASE, ".venv", "bin", "python")
REGIPY = os.path.join(BASE, ".venv", "bin", "regipy-dump")
DUMP = os.path.join(BASE, "00_README", "dump_pyregistry.py")
OUTDIR = {"regipy": os.path.join(BASE, "04_REGIPY_OUTPUT"),
          "python-registry": os.path.join(BASE, "05_PYREG_OUTPUT")}
SUFFIX = {"regipy": "_regipy.json", "python-registry": "_pyregistry.json"}
RAW = os.path.join(BASE, "06_RAW_RESULTS")
LOG = os.path.join(RAW, "replication_run_log.csv")
REPS = ["R1", "R2", "R3"]
FIELDS = ["run_id", "rep", "tool", "category", "hive_file", "sha256_before", "sha256_after",
          "baseline_sha256", "input_matches_baseline", "return_code", "status", "runtime_sec",
          "error_count", "parser_error", "output_file", "output_sha256"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_hive(name):
    for root, _, files in os.walk(os.path.join(BASE, "03_WORKING_COPY")):
        if name in files:
            return os.path.join(root, name)
    raise FileNotFoundError(name)


def embedded_errors(tool, path):
    """Jumlah error yang tertanam di JSON output (value ERROR, subkey error, is_corrupted)."""
    n = 0
    if tool == "python-registry":
        for r in json.load(open(path, encoding="utf-8")):
            for v in r["values"]:
                if v["name"] in ("__ERROR__", "__SUBKEY_ERROR__") or str(v["value"]).startswith("ERROR:"):
                    n += 1
    else:
        for line in open(path, encoding="utf-8"):
            if line.strip():
                n += sum(1 for v in json.loads(line)["values"] if v.get("is_corrupted"))
    return n


def main():
    hives = pd.read_csv(os.path.join(BASE, "02_GROUND_TRUTH", "registry_expected.csv"))[
        ["hive_file", "category"]].drop_duplicates()
    rows = []
    for rep in REPS:
        for tool in OUTDIR:
            os.makedirs(os.path.join(OUTDIR[tool], rep), exist_ok=False)
        os.makedirs(os.path.join(RAW, rep), exist_ok=False)
        for tool in ("regipy", "python-registry"):
            for _, h in hives.iterrows():
                src = find_hive(h["hive_file"])
                baseline = src.replace("03_WORKING_COPY", "01_BASELINE")
                stem = h["hive_file"].replace(".hive", "")
                out = os.path.join(OUTDIR[tool], rep, stem + SUFFIX[tool])
                before = sha256(src)
                base_hash = sha256(baseline) if os.path.exists(baseline) else "NA"
                cmd = ([REGIPY, src, "-o", out] if tool == "regipy" else [PY, DUMP, src, out])
                t0 = time.perf_counter()
                r = subprocess.run(cmd, capture_output=True, text=True)
                dt = time.perf_counter() - t0
                after = sha256(src)
                ok = r.returncode == 0 and os.path.exists(out)
                err_lines = [l for l in r.stderr.strip().splitlines() if l.strip()]
                with open(os.path.join(RAW, rep, f"{stem}_{tool}_run.txt"), "w", encoding="utf-8") as f:
                    f.write(f"COMMAND: {' '.join(os.path.relpath(c, BASE) if c.startswith(BASE) else c for c in cmd)}\n"
                            f"RETURN CODE: {r.returncode}\nRUNTIME_SEC: {dt:.4f}\n"
                            f"SHA256_BEFORE: {before}\nSHA256_AFTER: {after}\n"
                            f"STDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}\n")
                n_err = embedded_errors(tool, out) if ok else 1
                rows.append({
                    "run_id": f"DF04-{h['category'][:2].upper()}-{stem}-{rep}-{tool}",
                    "rep": rep, "tool": tool, "category": h["category"], "hive_file": h["hive_file"],
                    "sha256_before": before, "sha256_after": after, "baseline_sha256": base_hash,
                    "input_matches_baseline": int(before == base_hash == after),
                    "return_code": r.returncode, "status": "OK" if ok else "FAILED",
                    "runtime_sec": round(dt, 4), "error_count": n_err,
                    "parser_error": err_lines[-1] if (not ok and err_lines) else "-",
                    "output_file": os.path.relpath(out, BASE) if ok else "",
                    "output_sha256": sha256(out) if ok else ""})
                print(rep, tool, h["hive_file"], rows[-1]["status"], rows[-1]["runtime_sec"], flush=True)
    with open(LOG, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print("Wrote", LOG)


if __name__ == "__main__":
    sys.exit(main())

