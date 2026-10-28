# Dokumentasi Instalasi & Pengujian Tools (DF04 - Kelompok 4)

## 1. Lingkungan Sistem
- **Sistem Operasi**: macOS (Darwin arm64)
- **Python**: 3.13.7 (Virtual Environment `.venv`)

## 2. Tools dan Versi
Sesuai catatan di [`tool_versions.txt`](file:///Users/Xantares/WORKZEN/Digital%20Forensics/DF04_Kelompok4/00_README/tool_versions.txt):
- **regipy**: `v6.5.0` (CLI & Python library untuk Registry parsing)
- **python-registry**: `v1.3.1` (Python library independen oleh Willi Ballenthin)
- **pandas**: `v3.1.0` (Data manipulation & analisis metrik)
- **click**: `v8.5.0` (CLI framework pendukung `regipy`)
- **tabulate**: `v0.10.0` (CLI formatting pendukung `regipy`)

## 3. Hasil Uji Instalasi (Smoke Test)
Semua parser berhasil diuji coba pada working copy Registry hive (`[nr]-02-1_v15.hive`):
1. **regipy-parse-header**:
   - Signature: `b'regf'` (Valid Windows Registry Header)
   - Status: Berhasil membaca struktur header registry hive.
2. **regipy-dump**:
   - Status: Berhasil melakukan enumerasi dan dump subkey registry.
3. **dump_pyregistry.py** (`python-registry`):
   - Status: Berhasil melakukan recursive traversal dan mengekstrak 16 key records ke format JSON.

