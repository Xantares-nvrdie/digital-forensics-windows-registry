"""Langkah 5 (modul): bandingkan output JSON tiap parser terhadap ground truth.

Jalankan dari folder DF04_Kelompok4:
    .venv/bin/python 07_ANALYSIS/evaluate_artifacts.py

Input : 02_GROUND_TRUTH/registry_expected.csv, 04_REGIPY_OUTPUT/*.json (JSON Lines),
        05_PYREG_OUTPUT/*.json, 06_RAW_RESULTS/*_run.txt (untuk hive yang crash)
Output: 07_ANALYSIS/registry_item_results.csv (2 baris per artifact: regipy & python-registry)

Aturan klasifikasi (mengikuti EXPERIMENTAL_DESIGN.md bagian 4.1; tiap tool dinilai
terhadap ground truth sendiri-sendiri, tidak dibandingkan satu sama lain di sini):
  * Status ACTIVE / MODIFIED (target yang seharusnya terbaca):
      key (dan value bila ditentukan) ditemukan dan value cocok -> TP
      key ditemukan tetapi value tidak ada      -> FN
      key ditemukan, value ada tetapi tidak cocok -> FP (nilai salah/terkorupsi)
      key tidak ada, atau parser crash sebelum objek tercapai -> FN
  * Status DELETED / CORRUPTED / MANIPULATED (seharusnya TIDAK dilaporkan sebagai aktif):
      objek dilaporkan sebagai key/value aktif -> FP
      objek tidak dilaporkan, atau parser berhenti dengan exception -> TN
  * Ekspektasi 'TAMPERED_OR_EMPTY' (REG-M-006): value dianggap "dilaporkan" hanya jika
    tidak kosong dan bukan ERROR.
  * timestamp_match: sama persis setelah normalisasi ke UTC (selisih dicatat di notes).
  * Kolom yang tidak berlaku (tidak ada expected value / expected timestamp) diisi NA.
"""
import ast
import csv
import glob
import json
import os
import re
import unicodedata
from datetime import datetime, timezone

import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT = os.path.join(BASE, "02_GROUND_TRUTH", "registry_expected.csv")
OUT = os.path.join(BASE, "07_ANALYSIS", "registry_item_results.csv")
FIELDS = ["artifact_id", "category", "hive_file", "tool", "key_found", "value_found",
          "value_match", "timestamp_found", "timestamp_match", "parser_error",
          "classification", "notes"]
TOOLS = ["regipy", "python-registry"]


def norm_path(p):
    p = unicodedata.normalize("NFC", p).replace("/", "\\").rstrip("\\")
    return p.casefold()


def parse_ts(s):
    if not s:
        return None
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_output(tool, stem):
    """Kembalikan (records, error). records: {norm_path: {'ts':..,'values':{name: raw}}}."""
    if tool == "regipy":
        path = os.path.join(BASE, "04_REGIPY_OUTPUT", f"{stem}_regipy.json")
        log = os.path.join(BASE, "06_RAW_RESULTS", f"{stem}_regipy_run.txt")
    else:
        path = os.path.join(BASE, "05_PYREG_OUTPUT", f"{stem}_pyregistry.json")
        log = os.path.join(BASE, "06_RAW_RESULTS", f"{stem}_pyregistry_run.txt")
    if not os.path.exists(path):
        err = "no output file"
        if os.path.exists(log):
            lines = [l.strip() for l in open(log, encoding="utf-8") if l.strip()]
            err = lines[-1]
        return None, err
    recs = {}
    if tool == "regipy":
        rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        for r in rows:
            p = "ROOT" if r["path"] in ("\\", "") else "ROOT" + r["path"]
            recs.setdefault(norm_path(p), {"ts": r["timestamp"],
                                           "values": {v["name"]: v["value"] for v in r["values"]}})
    else:
        rows = json.load(open(path, encoding="utf-8"))
        for r in rows:
            recs.setdefault(norm_path(r["key_path"]), {
                "ts": r["timestamp"],
                "values": {v["name"]: v["value"] for v in r["values"]}})
    return recs, None


HEX = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def representations(raw):
    """Semua tafsiran nilai aktual yang masuk akal: set of bytes / str / list."""
    reps = {"bytes": set(), "str": set(), "list": []}
    if isinstance(raw, bool):
        raw = str(raw)
    if isinstance(raw, int):
        reps["str"].add(str(raw))
        return reps
    if isinstance(raw, list):
        reps["list"].append([str(x) for x in raw])
        return reps
    s = str(raw)
    reps["str"].add(s)
    reps["bytes"].add(s.encode("utf-8"))
    if s.startswith("["):
        try:
            reps["list"].append([str(x) for x in ast.literal_eval(s)])
        except Exception:
            pass
    if HEX.match(s):
        b = bytes.fromhex(s)
        reps["bytes"].add(b)
        try:
            reps["str"].add(b.decode("utf-16-le").rstrip("\x00"))
        except Exception:
            pass
    return reps


def strip_empty(lst):
    lst = list(lst)
    while lst and lst[-1] == "":
        lst.pop()
    return lst


def value_matches(expected, raw):
    reps = representations(raw)
    e = str(expected)
    if e.startswith("b'") or e.startswith('b"'):
        return ast.literal_eval(e) in reps["bytes"]
    if e.startswith("["):
        el = strip_empty([str(x) for x in ast.literal_eval(e)])
        return any(strip_empty(a) == el for a in reps["list"])
    return e in reps["str"]


def is_error_value(raw):
    return isinstance(raw, str) and raw.startswith("ERROR:")


def find_mangled(key, recs):
    """Cari key pada output yang namanya rusak encoding (karakter U+FFFD) tetapi sama dengan expected."""
    target = norm_path(key)
    for p in recs:
        if "\ufffd" in p and re.fullmatch(re.escape(p).replace("\ufffd", "."), target):
            return p
    return None


# Catatan observasi pasca-hoc; TIDAK mengubah klasifikasi (rule sudah dikunci di preregistration).
EXTRA_NOTES = {
    "REG-M-006": "GT menunjuk VALUE 0x01 (SZ), tetapi tampering di hive ini ada pada VALUE 0x03 (BINARY) "
                 "yang terbaca kosong tanpa error oleh kedua parser; perlu amandemen GT (lihat laporan)",
}


def evaluate(row, tool, recs, err):
    out = _evaluate(row, tool, recs, err)
    extra = EXTRA_NOTES.get(row["artifact_id"])
    if extra:
        out["notes"] = f"{out['notes']}; {extra}"
    return out


def _evaluate(row, tool, recs, err):
    status = row["expected_status"]
    active_like = status in ("ACTIVE", "MODIFIED")
    out = dict(artifact_id=row["artifact_id"], category=row["category"],
               hive_file=row["hive_file"], tool=tool, parser_error="-")
    notes = []
    if recs is None:
        out.update(key_found=0, value_found=0 if pd.notna(row["value_name"]) else "NA",
                   value_match=0 if pd.notna(row["value_name"]) else "NA",
                   timestamp_found=0, timestamp_match=0 if pd.notna(row["expected_timestamp"]) else "NA",
                   parser_error=err)
        if active_like:
            out["classification"] = "FN"
            notes.append("Parser crash sebelum objek tercapai (FN sesuai rule)")
        else:
            out["classification"] = "TN"
            notes.append(f"Parser berhenti dengan exception; objek {status} tidak dilaporkan aktif")
        out["notes"] = "; ".join(notes)
        return out

    key = row["key_path"]
    rec = recs.get(norm_path(key)) if key != "HEADER" else None
    key_found = rec is not None
    vname = row["value_name"] if pd.notna(row["value_name"]) else None
    value_found = value_match = "NA"
    raw = None
    if key == "HEADER":
        # Header tidak diekspos pada JSON kedua parser; parser tidak crash tetapi tidak ada data header.
        out.update(key_found=0, value_found=0, value_match=0, timestamp_found=0,
                   timestamp_match="NA", classification="FN" if active_like else "TN",
                   notes="Header tidak diekspos oleh output JSON")
        return out
    if vname is not None and key_found:
        names = {n.casefold(): n for n in rec["values"]}
        if vname.casefold() in names:
            raw = rec["values"][names[vname.casefold()]]
            if is_error_value(raw):
                value_found = 0
                out["parser_error"] = raw[:120]
                notes.append("Value tidak terbaca (ERROR)")
            elif str(row["expected_value"]) == "TAMPERED_OR_EMPTY":
                value_found = 1 if str(raw) != "" else 0
            else:
                value_found = 1
        else:
            value_found = 0
        if value_found == 1 and pd.notna(row["expected_value"]) and str(row["expected_value"]) != "TAMPERED_OR_EMPTY":
            value_match = 1 if value_matches(row["expected_value"], raw) else 0
        elif str(row["expected_value"]) == "TAMPERED_OR_EMPTY":
            value_match = "NA"
        else:
            value_match = 0 if value_found == 0 else "NA"
    elif vname is not None and not key_found:
        value_found, value_match = 0, 0

    ts_found = 1 if key_found and rec["ts"] else 0
    ts_match = "NA"
    if pd.notna(row["expected_timestamp"]):
        ts_match = 0
        if ts_found:
            delta = abs((parse_ts(rec["ts"]) - parse_ts(row["expected_timestamp"])).total_seconds())
            ts_match = 1 if delta == 0 else 0
            if delta:
                notes.append(f"selisih timestamp {delta * 1e6:.0f} us")
    out.update(key_found=int(key_found), value_found=value_found, value_match=value_match,
               timestamp_found=ts_found, timestamp_match=ts_match)

    if active_like:
        if vname is None:
            cls = "TP" if key_found else "FN"
        elif not key_found or value_found == 0:
            cls = "FN"
        else:
            cls = "TP" if value_match == 1 else "FP"
            if cls == "FP":
                notes.append(f"Value berbeda dari expected (aktual={str(raw)[:60]!r})")
        if cls == "FN":
            if not key_found:
                mangled = find_mangled(key, recs)
                notes.append("Key tidak ditemukan pada output"
                             + (f"; ada key dengan nama termangle U+FFFD: {mangled!a}" if mangled else ""))
            else:
                notes.append("Key ditemukan tetapi value tidak ada/tidak terbaca")
    else:
        reported = key_found if vname is None else (key_found and value_found == 1)
        cls = "FP" if reported else "TN"
        notes.append("Objek " + status + (" dilaporkan sebagai aktif" if reported else " tidak dilaporkan"))
    out["classification"] = cls
    out["notes"] = "; ".join(notes) if notes else "Cocok dengan ground truth"
    return out


def main():
    gt = pd.read_csv(GT)
    cache, results = {}, []
    for _, row in gt.iterrows():
        stem = row["hive_file"].replace(".hive", "")
        for tool in TOOLS:
            if (tool, stem) not in cache:
                cache[(tool, stem)] = load_output(tool, stem)
            recs, err = cache[(tool, stem)]
            results.append(evaluate(row, tool, recs, err))
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(results)
    df = pd.DataFrame(results)
    print(f"Wrote {len(df)} rows to {OUT}")
    print(pd.crosstab([df["tool"], df["category"]], df["classification"]))

    # Langkah 5.4 (tahap 2): setelah masing-masing dinilai terhadap ground truth,
    # bandingkan kedua tool pada artifact yang sama.
    a = df[df["tool"] == "regipy"].set_index("artifact_id")
    b = df[df["tool"] == "python-registry"].set_index("artifact_id")
    pair = a[["category", "hive_file", "classification"]].join(
        b[["classification"]], rsuffix="_pyreg").rename(columns={"classification": "classification_regipy"})
    dis = pair[pair["classification_regipy"] != pair["classification_pyreg"]].reset_index()
    dis.to_csv(os.path.join(BASE, "07_ANALYSIS", "tool_disagreement.csv"), index=False)
    print(f"\nDisagreement klasifikasi: {len(dis)} dari {len(pair)} artifact")
    print(dis.to_string(index=False))


if __name__ == "__main__":
    main()
