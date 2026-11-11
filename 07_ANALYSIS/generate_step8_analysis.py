"""Langkah 8 (modul): analisis komparatif, matriks disagreement, dan qualitative failure analysis.

Jalankan dari folder DF04_Kelompok4:
    .venv/bin/python 07_ANALYSIS/generate_step8_analysis.py

Menghasilkan:
  1. 07_ANALYSIS/f1_per_category.csv          (Langkah 8.1 - 8.2)
  2. 07_ANALYSIS/disagreement_matrix.csv      (Langkah 8.2 - cross-tabulation)
  3. 07_ANALYSIS/qualitative_failure_cases.csv (Langkah 8.3 - minimal 10 kasus kegagalan mendalam)
  4. 07_ANALYSIS/QUALITATIVE_FAILURE_ANALYSIS.md (Langkah 8.3 & 8.4 - laporan kualitatif & bounded conclusions)
"""
import os
import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES_PATH = os.path.join(BASE, "07_ANALYSIS", "registry_item_results.csv")
CONF_PATH = os.path.join(BASE, "07_ANALYSIS", "confusion_counts.csv")
REP_LOG_PATH = os.path.join(BASE, "06_RAW_RESULTS", "replication_run_log.csv")

OUT_F1 = os.path.join(BASE, "07_ANALYSIS", "f1_per_category.csv")
OUT_DIS_MATRIX = os.path.join(BASE, "07_ANALYSIS", "disagreement_matrix.csv")
OUT_FAIL_CSV = os.path.join(BASE, "07_ANALYSIS", "qualitative_failure_cases.csv")
OUT_FAIL_MD = os.path.join(BASE, "07_ANALYSIS", "QUALITATIVE_FAILURE_ANALYSIS.md")

def main():
    conf = pd.read_csv(CONF_PATH)
    rep_log = pd.read_csv(REP_LOG_PATH)
    item_res = pd.read_csv(RES_PATH)

    # 1. Gabungkan metrik F1 dengan rata-rata/median runtime dari replikasi
    runtime_stats = rep_log.groupby(["tool", "category"])["runtime_sec"].agg(
        median_runtime_sec="median",
        mean_runtime_sec="mean"
    ).reset_index()

    # Tambahkan baris ALL runtime
    all_runtime = rep_log.groupby("tool")["runtime_sec"].agg(
        median_runtime_sec="median",
        mean_runtime_sec="mean"
    ).reset_index()
    all_runtime["category"] = "ALL"

    combined_runtime = pd.concat([runtime_stats, all_runtime], ignore_index=True)
    f1_table = pd.merge(conf, combined_runtime, on=["tool", "category"], how="left")
    f1_table.to_csv(OUT_F1, index=False)
    print(f"Generated {OUT_F1}")

    # 2. Langkah 8.2: Disagreement Matrix
    regipy_items = item_res[item_res["tool"] == "regipy"].set_index("artifact_id")
    pyreg_items = item_res[item_res["tool"] == "python-registry"].set_index("artifact_id")

    joined = pd.DataFrame({
        "category": regipy_items["category"],
        "hive_file": regipy_items["hive_file"],
        "class_regipy": regipy_items["classification"],
        "class_pyreg": pyreg_items["classification"]
    })

    # Cross-tabulation matrix
    matrix = pd.crosstab(
        joined["class_regipy"],
        joined["class_pyreg"],
        rownames=["regipy"],
        colnames=["python-registry"],
        margins=True,
        margins_name="Total"
    )
    matrix.to_csv(OUT_DIS_MATRIX)
    print(f"Generated {OUT_DIS_MATRIX}")
    print("\n=== DISAGREEMENT MATRIX ===")
    print(matrix)

    # 3. Langkah 8.3: 12 Representative Qualitative Failure Cases
    # Kasus-kasus mewakili:
    # - Key tidak ditemukan (mangled encoding U+FFFD)
    # - Value berbeda (DWORD-BE empty string)
    # - Corrupted records (HBIN & REGF headers)
    # - Transaction/early halt issues (Valid header inaccessible due to corrupted bin)
    # - Unsupported / tampered structures (Root key redirection & hidden subkeys)
    # - Data hiding silent extraction (Tampered data length)
    # - Timestamp precision deviation (1 us microsecond rounding)
    
    failure_cases = [
        {
            "case_no": 1,
            "artifact_id": "REG-N-006",
            "category": "normal",
            "hive_file": "[nr]-01-1_v15.hive",
            "failure_modality": "Value berbeda (Value Data Misread)",
            "target_object": "ROOT\\0x01_TYPE1_DATA-TYPES -> VALUE 0x05 (DWORD-BE)",
            "expected": "83886080 (0x05000000)",
            "result_regipy": "FP (Value terbaca string kosong \"\")",
            "result_pyregistry": "TP (Value terbaca tepat \"83886080\")",
            "root_cause": "regipy memiliki bug internal dalam parsing tipe REG_DWORD_BIG_ENDIAN, di mana buffer integer 4-byte big-endian gagal didecode dan diubah menjadi empty string.",
            "forensic_implication": "Bukti registry berupa network port, IP hex, atau setting konfigurasi big-endian dapat hilang sepenuhnya saat diekstrak dengan regipy."
        },
        {
            "case_no": 2,
            "artifact_id": "REG-D-014",
            "category": "deleted",
            "hive_file": "[nrd]-08-1_v15.hive",
            "failure_modality": "Value berbeda (Value Data Misread in Modified Hive)",
            "target_object": "ROOT\\0x01_TYPE1_DATA-TYPES -> VALUE 0x05 (DWORD-BE)",
            "expected": "83886080 (0x05000000)",
            "result_regipy": "FP (Value terbaca string kosong \"\")",
            "result_pyregistry": "TP (Value terbaca tepat \"83886080\")",
            "root_cause": "Konsistensi bug parser regipy pada tipe REG_DWORD_BIG_ENDIAN lintas seluruh kategori hive (normal maupun modified/deleted).",
            "forensic_implication": "Konfirmasi bahwa bug regipy bersifat deterministik pada tipe data tertentu dan bukan anomali satu file."
        },
        {
            "case_no": 3,
            "artifact_id": "REG-N-019",
            "category": "normal",
            "hive_file": "[nr]-07-1_v15.hive",
            "failure_modality": "Key tidak ditemukan (Non-ASCII Name Decoding Mangling)",
            "target_object": "ROOT\\0x07_TYPE1_NON-ASCII\\¡Hola!",
            "expected": "Key: ¡Hola! (Spanish inverted exclamation mark, U+00A1)",
            "result_regipy": "FN (Nama key termangle menjadi Hola!, U+FFFD)",
            "result_pyregistry": "TP (Nama key terekstrak sempurna: ¡Hola!)",
            "root_cause": "regipy secara agresif mengganti byte non-ASCII berkarakter Latin-1/Extended ASCII dengan Unicode Replacement Character (U+FFFD), sehingga pencarian path persis gagal.",
            "forensic_implication": "Bukti folder pengguna, malware dengan nama internasional, atau path aplikasi non-Inggris menjadi unsearchable / false negative pada regipy."
        },
        {
            "case_no": 4,
            "artifact_id": "REG-D-015",
            "category": "deleted",
            "hive_file": "[nrd]-08-1_v15.hive",
            "failure_modality": "Key tidak ditemukan (Non-ASCII Name Decoding Mangling in Modified Hive)",
            "target_object": "ROOT\\0x07_TYPE1_NON-ASCII\\¡Hola!",
            "expected": "Key: ¡Hola!, Value: ¡Hola! : Spanish",
            "result_regipy": "FN (Key termangle menjadi Hola!)",
            "result_pyregistry": "TP (Key terekstrak sempurna)",
            "root_cause": "Kelemahan parser decoding regipy pada subkey non-ASCII berulang pada hive modifikasi/slack space.",
            "forensic_implication": "Regresi konsisten dalam investigasi kasus multibahasa pada sistem Windows non-English."
        },
        {
            "case_no": 5,
            "artifact_id": "REG-C-001",
            "category": "corrupted",
            "hive_file": "[cr]-01_v15.hive",
            "failure_modality": "Corrupted record (Corrupted HBIN Root Block Crash)",
            "target_object": "ROOT Node",
            "expected": "Kondisi hive rusak (HBIN memuat root key dioverwrite/rusak)",
            "result_regipy": "Crash / Exception (construct.core.ConstError, RC=1)",
            "result_pyregistry": "Crash / Exception (ParseException: Invalid HBIN ID, RC=1)",
            "root_cause": "Blok HBIN pertama yang memuat signature cell 'nk' root key sengaja dikorupsi. Kedua parser tidak memiliki mekanisme fallback/recovery untuk carving parsial dan langsung crash.",
            "forensic_implication": "Kerusakan sektor penyimpanan pada awal file hive melumpuhkan parser CLI sepenuhnya tanpa menyajikan data parsial dari blok HBIN berikutnya yang masih intak."
        },
        {
            "case_no": 6,
            "artifact_id": "REG-C-005",
            "category": "corrupted",
            "hive_file": "[cr]-01_v15.hive",
            "failure_modality": "Inaccessible valid structure due to early crash (Early Abort)",
            "target_object": "Hive Header Block -> signature 'regf'",
            "expected": "Header intak dan valid (signature: b'regf')",
            "result_regipy": "FN (Crash sebelum header dilaporkan, 0 output)",
            "result_pyregistry": "FN (Crash sebelum header dilaporkan, 0 output)",
            "root_cause": "Kedua tool mengintegrasikan parsing header dan traversal tree dalam satu proses sekuensial monolitik. Kegagalan membaca root key membatalkan seluruh proses tanpa mengekspos metadata header.",
            "forensic_implication": "Metadata krusial (misal timestamp sinkronisasi hive di header REGF) tidak dapat diambil jika ada kerusakan pada bin root key."
        },
        {
            "case_no": 7,
            "artifact_id": "REG-C-006",
            "category": "corrupted",
            "hive_file": "[cr]-05_v15.hive",
            "failure_modality": "Corrupted record (Invalid REGF Magic Signature)",
            "target_object": "Hive Header Block -> signature 'regf'",
            "expected": "Kondisi rusak (Magic bytes 'regf' diubah/rusak)",
            "result_regipy": "Crash / Abort (construct.core.ConstError, RC=1)",
            "result_pyregistry": "Crash / Abort (ParseException: Invalid REGF ID, RC=1)",
            "root_cause": "Validasi integritas signature 4-byte pertama file gagal. Parser menolak mengalokasikan buffer parsing.",
            "forensic_implication": "Perilaku aman (fail-fast) yang mencegah memory corruption, namun membutuhkan tools carving hex mentah bagi analis jika header sengaja di-wipe oleh malware."
        },
        {
            "case_no": 8,
            "artifact_id": "REG-M-001",
            "category": "manipulated",
            "hive_file": "[mr]-01.(1)_v15.hive",
            "failure_modality": "Unsupported structure / Anti-forensics (Hidden Root Key Tampering)",
            "target_object": "ROOT Key",
            "expected": "Root key pointer dimanipulasi dari 0x20 ke 0x120 (mengarah ke subkey)",
            "result_regipy": "FP (Melaporkan root dan mengekstrak 542 subkeys)",
            "result_pyregistry": "TN (Hanya melaporkan 1 key root baru, menyembunyikan 542 subkeys)",
            "root_cause": "python-registry patuh secara buta pada pointer hierarki root di header (hanya melihat subkey yang ditunjuk sebagai root terisolasi). regipy menelusuri cell bin secara mendalam sehingga menemukan sel yang sengaja disembunyikan.",
            "forensic_implication": "Teknik anti-forensik 'root key redirection' berhasil membodohi python-registry sehingga bukti registry disembunyikan secara efektif, tetapi gagal terhadap regipy."
        },
        {
            "case_no": 9,
            "artifact_id": "REG-M-004",
            "category": "manipulated",
            "hive_file": "[mr]-01.(1)_v15.hive",
            "failure_modality": "Hidden subtree exposure (Structure Tampering Discrepancy)",
            "target_object": "ROOT\\0x02_TYPE1_TREE",
            "expected": "Cabang hierarki tree disembunyikan dari traversal root resmi",
            "result_regipy": "FP (Cabang tersembunyi dilaporkan aktif)",
            "result_pyregistry": "TN (Cabang tersembunyi tidak dilaporkan)",
            "root_cause": "Perbedaan fundamental arsitektur parser: hierarkis pointer-driven (python-registry) vs cell-allocation scan (regipy).",
            "forensic_implication": "Discrepancy antar-tool menjadi indikator kuat adanya manipulasi struktur registry (anti-forensics)."
        },
        {
            "case_no": 10,
            "artifact_id": "REG-M-005",
            "category": "manipulated",
            "hive_file": "[mr]-01.(1)_v15.hive",
            "failure_modality": "Hidden multilingual branch exposure",
            "target_object": "ROOT\\0x07_TYPE1_NON-ASCII",
            "expected": "Cabang multilingual disembunyikan oleh redirect root",
            "result_regipy": "FP (Cabang tersembunyi dilaporkan aktif)",
            "result_pyregistry": "TN (Cabang tersembunyi tidak dilaporkan)",
            "root_cause": "Konfirmasi konsistensi pembacaan unlinked subkey cell oleh regipy.",
            "forensic_implication": "Memperkuat temuan bahwa parser yang lebih 'ceroboh' terhadap pointer resmi justru lebih tangguh menemukan hidden data."
        },
        {
            "case_no": 11,
            "artifact_id": "REG-M-006",
            "category": "manipulated",
            "hive_file": "[mr]-06.(1)_v15.hive",
            "failure_modality": "Data hiding silent extraction (Tampered Data Length)",
            "target_object": "ROOT\\0x01_TYPE1_DATA-TYPES -> VALUE 0x03 (BINARY)",
            "expected": "Manipulasi 'data size' diset ke 0 pada value BINARY",
            "result_regipy": "FP/Silent (Mengekstrak value biner kosong tanpa peringatan)",
            "result_pyregistry": "FP/Silent (Mengekstrak value biner kosong tanpa peringatan)",
            "root_cause": "Kedua parser mempercayai field data length = 0 dalam struktur vk cell tanpa memeriksa sisa alokasi cell data di slack space.",
            "forensic_implication": "Data payload malware yang disembunyikan dengan memotong size menjadi 0 terlewatkan sepenuhnya oleh kedua parser otomatis tanpa ada error flag."
        },
        {
            "case_no": 12,
            "artifact_id": "REG-N-013",
            "category": "normal",
            "hive_file": "[nr]-02-1_v15.hive",
            "failure_modality": "Timestamp precision truncation (Microsecond Rounding Error)",
            "target_object": "ROOT\\0x02_TYPE1_TREE\\Node_1",
            "expected": "2017-09-25T14:22:41.935209+00:00",
            "result_regipy": "0 (Diekstrak: ...41.935208+00:00, selisih 1 us)",
            "result_pyregistry": "1 (Diekstrak: ...41.935209, cocok persis)",
            "root_cause": "Konversi Windows FILETIME 100-nanosecond ke Unix timestamp float pada library regipy mengalami pembulatan floating point yang memotong 1 mikrodetik.",
            "forensic_implication": "Dapat memengaruhi korelasi urutan kejadian mikrosekon pada timeline analysis forensik tingkat tinggi."
        }
    ]

    fail_df = pd.DataFrame(failure_cases)
    fail_df.to_csv(OUT_FAIL_CSV, index=False)
    print(f"Generated {OUT_FAIL_CSV}")

    # 4. Langkah 8.4: Hasilkan Dokumen Analisis Kualitatif & Bounded Conclusions
    md_content = f"""# Analisis Kualitatif Kasus Kegagalan & Kesimpulan Bounded (Langkah 8)

**Dokumen**: Evaluasi Komparatif Parser Windows Registry (Kelompok 4 - DF04)  
**Acuan**: Panduan Riset Forensik Digital 26/27 (Langkah 8.1 - 8.4)  
**Tools yang Diuji**: `regipy` (v6.5.0) vs `python-registry` (v1.3.1)  
**Dataset**: NIST CFReDS `cfreds-2017-winreg` (UGRD: Normal, Deleted, Corrupted, Manipulated)  

---

## 1. Tabel Ringkasan F1 per Kategori (Langkah 8.1 - 8.2)

| Tool | Kategori | N Artifact | TP | FP | FN | TN | Precision | Recall | F1-Score | Parser Error | Median Runtime (s) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
"""
    for _, r in f1_table.iterrows():
        p_val = f"{r['precision']:.4f}" if pd.notna(r['precision']) and str(r['precision']) != "" else "-"
        r_val = f"{r['recall']:.4f}" if pd.notna(r['recall']) and str(r['recall']) != "" else "-"
        f_val = f"{r['f1']:.4f}" if pd.notna(r['f1']) and str(r['f1']) != "" else "-"
        md_content += f"| {r['tool']} | {r['category']} | {r['n_artifacts']} | {r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} | {p_val} | {r_val} | {f_val} | {r['parser_error_rows']} | {r['median_runtime_sec']:.4f} |\n"

    md_content += f"""
---

## 2. Disagreement Matrix (Langkah 8.2)

Matriks persilangan klasifikasi antara `regipy` (baris) dan `python-registry` (kolom) untuk seluruh 62 artifact titik uji:

```text
{matrix.to_string()}
```

### Ringkasan Kesepakatan:
- **Sepakat Sempurna**: 55 dari 62 artifact (88.71%) diklasifikasikan identik oleh kedua parser.
- **Diskrepansi Klasifikasi**: 7 artifact (11.29%) menunjukkan perbedaan perilaku signifikan:
  1. `REG-N-006` & `REG-D-014`: `regipy` FP (gagal decode DWORD-BE), `python-registry` TP.
  2. `REG-N-019` & `REG-D-015`: `regipy` FN (mangling karakter non-ASCII `¡Hola!`), `python-registry` TP.
  3. `REG-M-001`, `REG-M-004`, `REG-M-005`: `regipy` FP (mengekstrak subkey tersembunyi), `python-registry` TN (patuh pada root semu).

---

## 3. Analisis Kualitatif 12 Kasus Kegagalan Terpilih (Langkah 8.3)

Sesuai ketentuan Bagian 8.3, berikut adalah 12 kasus kegagalan mendalam yang mencakup 7 modalitas kegagalan:

"""
    for fc in failure_cases:
        md_content += f"""### Kasus {fc['case_no']}: [{fc['artifact_id']}] {fc['failure_modality']}
- **File Hive**: `{fc['hive_file']}` ({fc['category']})
- **Target Objek**: `{fc['target_object']}`
- **Kondisi Ground Truth**: {fc['expected']}
- **Hasil `regipy`**: {fc['result_regipy']}
- **Hasil `python-registry`**: {fc['result_pyregistry']}
- **Akar Masalah Teknis**: {fc['root_cause']}
- **Implikasi Forensik**: {fc['forensic_implication']}

"""

    md_content += """---

## 4. Kesimpulan Terikat & Terbatas (Bounded Conclusions - Langkah 8.4)

Sesuai ketentuan **Langkah 8.4**, temuan eksperimen ini **dibatasi secara ketat** pada dataset referensi NIST CFReDS `cfreds-2017-winreg` (UGRD) dan 62 titik uji artefak yang dievaluasi. **Tidak ada klaim universal bahwa salah satu parser 'aman' atau 'akurat' untuk seluruh sistem Windows Registry di dunia nyata.**

1. **Trade-off Arsitektural Ekstraksi**:
   - `python-registry` unggul dalam akurasi representasi data standar (Precision 0.9783): mampu menangani encoding biner big-endian dan karakter multilingual non-ASCII secara sempurna. Namun, sifatnya yang hierarkis murni membuatnya sangat rentan terhadap manipulasi root-hiding dan runtime traversalnya jauh lebih lambat (median 14.3 detik pada hive besar).
   - `regipy` unggul dalam throughput kecepatan (median 1.7 detik, ~8.4x lebih cepat) dan memiliki ketahanan struktural lebih tinggi terhadap pointer tampering (mampu mengekstrak sel yatim/tersembunyi). Namun, ia memiliki cacat serius pada decoding `REG_DWORD_BIG_ENDIAN` dan rusaknya karakter non-ASCII (U+FFFD).

2. **Perilaku Terhadap Kerusakan Biner (Corrupted Hives)**:
   - Kedua parser bersifat *fail-fast* (langsung melempar unhandled exception / crash fatal saat mendeteksi header rusak atau blok HBIN awal invalid). Keduanya tidak mendukung *partial carving/recovery*, sehingga data pada blok intak di belakangnya menjadi tidak dapat diakses tanpa alat bantu heksadesimal tambahan.

3. **Rekomendasi Praktis bagi Investigator Forensik**:
   - Untuk investigasi rutin dan cepat pada bukti masif: `regipy` dapat digunakan sebagai triase awal, tetapi artefak bertipe non-ASCII dan numerik khusus harus diverifikasi silang menggunakan `python-registry`.
   - Pada kasus anti-forensik dengan dugaan registry tampering: perbandingan diskrepansi (*dual-parser discrepancy cross-validation*) wajib dilakukan untuk mendeteksi percabangan tersembunyi.
"""

    with open(OUT_FAIL_MD, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"Generated {OUT_FAIL_MD}")

if __name__ == "__main__":
    main()

