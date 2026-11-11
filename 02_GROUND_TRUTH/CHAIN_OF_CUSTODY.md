# Form Chain of Custody & Evidence Manifest Digital
**Modul 4: Windows Registry Forensics Menggunakan Reference Dataset**  
**Standar Acuan**: Panduan Riset Forensik Digital 26/27 (Bagian 4.2, 8.2, dan 8.3)

---

## 1. Identitas Kasus dan Sub-Riset

| Atribut Kasus | Keterangan |
| :--- | :--- |
| **Kode Kasus / Kelompok** | DF04 - Kelompok 4 |
| **Topik Sub-Riset** | Windows Registry Forensics Menggunakan Reference Dataset |
| **Objek Utama** | NIST CFReDS `cfreds-2017-winreg` (User-Generated Reference Data - UGRD) |
| **Penyusun / Operator** | Bintang Fajar Putra Pamungkas (2405073) & Shidqi Rasyad Firjatulah (2408156) |
| **Lingkungan Pengujian** | macOS (Darwin arm64) / Linux WSL / Windows |
| **Tools Hashing** | SHA-256 (`sha256sum` / `shasum -a 256` / `Get-FileHash`) |

---

## 2. Evidence Manifest (Standar Modul Bagian 8.2)

> **Ketentuan Pengisian (Bagian 4.2 & 8.2):**
> - Catat setiap file bukti digital segera setelah dibuat atau diunduh.
> - `evidence_id`: Berikan kode unik bukti (contoh: `E001`, `E002`, `E001-W1` untuk working copy dari `E001`).
> - `status`: Tuliskan `baseline` untuk master asli atau `working copy` untuk salinan operasional.

| evidence_id | filename | size_bytes | sha256 | source | created/downloaded_at | status |
| :--- | :--- | :---: | :--- | :--- | :---: | :---: |
| E001 | `01_BASELINE/cfreds-2017-winreg_ugrd-nr.7z` | 4309307 | `2694d01c97e44ab0da3c7998000f6019caa5d9cd8cfe7edab5f2eeb4199d051c` | NIST CFReDS Portal | 2026-10-28 11:38 | baseline |
| E001-W1 | `03_WORKING_COPY/ugrd-nr/` | 148799488 | `match YES` | copy of E001 | 2026-10-28 11:50 | working copy |
| E002 | `01_BASELINE/cfreds-2017-winreg_ugrd-nrd.7z` | 83526 | `4893519f74426233d5891d3520f0aec85af5f2b7d83342de21ba9c73fb82e789` | NIST CFReDS Portal | 2026-10-28 11:38 | baseline |
| E002-W1 | `03_WORKING_COPY/ugrd-nrd/` | 159962112 | `match YES` | copy of E002 | 2026-10-28 11:50 | working copy |
| E003 | `01_BASELINE/cfreds-2017-winreg_ugrd-cr.7z` | 14929 | `65708184a8419890d8006326075ca7185146971c9e605d1ef9f94eb79fa6523d` | NIST CFReDS Portal | 2026-10-28 11:38 | baseline |
| E003-W1 | `03_WORKING_COPY/ugrd-cr/` | 27534324 | `match YES` | copy of E003 | 2026-10-28 11:50 | working copy |
| E004 | `01_BASELINE/cfreds-2017-winreg_ugrd-mr.7z` | 37926 | `e071c76d0b4cb85ea64c41a8b913d49c8bb88fa1dcfc27b9a4ee8327d951fcfc` | NIST CFReDS Portal | 2026-10-28 11:38 | baseline |
| E004-W1 | `03_WORKING_COPY/ugrd-mr/` | 104510936 | `match YES` | copy of E004 | 2026-10-28 11:50 | working copy |
| E005 | `02_GROUND_TRUTH/cfreds-2017-winreg.pdf` | 1854543 | `c6b72da66986d396af75d45044e677f7256ecfb8afc514be8a74571e56d0d9f3` | NIST CFReDS Portal | 2026-10-28 11:48 | baseline |

---

## 3. Log Chain of Custody Digital (Standar Modul Bagian 8.3)

> **Ketentuan Pengisian (Bagian 4.2 & 8.3):**
> - Catat kronologis penanganan bukti dari proses akuisisi/unduh, duplikasi, hashing, hingga eksekusi tool.
> - `action`: Tindakan yang dilakukan (misal: `download/create`, `copy`, `extract`, `hash_verification`, `parsing`).
> - `from` & `to`: Lokasi asal dan tujuan bukti (misal: `source` -> `01_BASELINE`, `01_BASELINE` -> `03_WORKING_COPY`).
> - `hash/verification`: Nilai hash SHA-256 atau status verifikasi integritas (`SHA-256 ...` / `match YES` / `mismatch NO`).
> - `operator`: Nama mahasiswa penanggung jawab tindakan.
> - **Aturan Baku**: File baseline **DILARANG DIUBAH** setelah hash awal dicatat. Semua pemrosesan hanya boleh dilakukan pada working copy.

| timestamp | evidence_id | action | from | to | hash/verification | operator | notes |
| :---: | :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-10-28 11:38 | E001 | download/create | source | 01_BASELINE | `2694d01c97e44ab0da3c7998000f6019caa5d9cd8cfe7edab5f2eeb4199d051c` | Bintang Fajar | baseline archive downloaded |
| 2026-10-28 11:49 | E001 | extract | 01_BASELINE | 01_BASELINE/ugrd-nr | match YES | Bintang Fajar | extracted without deleting archive |
| 2026-10-28 11:50 | E001-W1 | copy | 01_BASELINE | 03_WORKING_COPY | match YES | Bintang Fajar | working copy created for analysis |
| 2026-10-28 11:38 | E002 | download/create | source | 01_BASELINE | `4893519f74426233d5891d3520f0aec85af5f2b7d83342de21ba9c73fb82e789` | Bintang Fajar | baseline archive downloaded |
| 2026-10-28 11:49 | E002 | extract | 01_BASELINE | 01_BASELINE/ugrd-nrd | match YES | Bintang Fajar | extracted without deleting archive |
| 2026-10-28 11:50 | E002-W1 | copy | 01_BASELINE | 03_WORKING_COPY | match YES | Bintang Fajar | working copy created for analysis |
| 2026-10-28 11:38 | E003 | download/create | source | 01_BASELINE | `65708184a8419890d8006326075ca7185146971c9e605d1ef9f94eb79fa6523d` | Bintang Fajar | baseline archive downloaded |
| 2026-10-28 11:49 | E003 | extract | 01_BASELINE | 01_BASELINE/ugrd-cr | match YES | Bintang Fajar | extracted without deleting archive |
| 2026-10-28 11:50 | E003-W1 | copy | 01_BASELINE | 03_WORKING_COPY | match YES | Bintang Fajar | working copy created for analysis |
| 2026-10-28 11:38 | E004 | download/create | source | 01_BASELINE | `e071c76d0b4cb85ea64c41a8b913d49c8bb88fa1dcfc27b9a4ee8327d951fcfc` | Bintang Fajar | baseline archive downloaded |
| 2026-10-28 11:49 | E004 | extract | 01_BASELINE | 01_BASELINE/ugrd-mr | match YES | Bintang Fajar | extracted without deleting archive |
| 2026-10-28 11:50 | E004-W1 | copy | 01_BASELINE | 03_WORKING_COPY | match YES | Bintang Fajar | working copy created for analysis |
| 2026-10-28 11:48 | E005 | download/create | source | 02_GROUND_TRUTH | `c6b72da66986d396af75d45044e677f7256ecfb8afc514be8a74571e56d0d9f3` | Bintang Fajar | ground truth specification PDF |
| 2026-10-28 12:06 | E001-W1 | parsing_smoketest | 03_WORKING_COPY | 00_README | match YES | Bintang Fajar | smoke test regipy-dump and python-registry on [nr]-02-1_v15.hive |
| 2026-10-28 12:18 | GT-01 | catalog_ground_truth | 02_GROUND_TRUTH | 02_GROUND_TRUTH/registry_expected.csv | match YES | Bintang Fajar | cataloged 62 expected test points from NIST GT PDF |
| 2026-10-28 12:33 | EXP-01 | preregistration | 00_README | 00_README/EXPERIMENTAL_DESIGN.md | match YES | Bintang Fajar | finalized Week 2 experimental matrix and research design |
| 2026-10-29 11:03 | E001-W1;E002-W1;E003-W1 | pilot_extraction | 03_WORKING_COPY | 04_REGIPY_OUTPUT/05_PYREG_OUTPUT | match YES | Shidqi Rasyad | Week 3 pilot extraction on [nr]-01-1 [nrd]-01-1 and crash test on [cr]-01 |
| 2026-11-11 21:28 | E001-W1..E004-W1 | mass_cross_validation_extraction | 03_WORKING_COPY | 04_REGIPY_OUTPUT/05_PYREG_OUTPUT | match YES | Bintang Fajar | Week 4 mass traversal across all 11 hives with python-registry and regipy; captured crash tracebacks for corrupted hives |
| 2026-11-11 22:00 | E001-W1..E004-W1 | ground_truth_comparison | 04_REGIPY_OUTPUT/05_PYREG_OUTPUT | 07_ANALYSIS/registry_item_results.csv | match YES | Bintang Fajar | Week 4 Langkah 5: 62 artifact x 2 tool dibandingkan ke ground truth via evaluate_artifacts.py; regipy run log untuk [cr]-01 dan [cr]-05 ditambahkan |
| 2026-11-11 22:05 | E001-W1..E004-W1 | confusion_classification | 07_ANALYSIS/registry_item_results.csv | 07_ANALYSIS/confusion_counts.csv; 07_ANALYSIS/unsupported_error_cases.csv | input `registry_item_results.csv` sha256=`4829e1164d5feb342c5ae76368df3de071f850265f31dab597a5b1dcb34696b9`; `confusion_counts.csv` sha256=`2467c2d74416fe817b5e65fa68b9ad0f55ba79d03eae7e63e8c3b99044cb6ebe`; `unsupported_error_cases.csv` sha256=`76c7a52b579270bbc512b2c781500bdfa2c4f8bd0a94e767dd436c3c93a6efa5` | Bintang Fajar | Week 6 Langkah 6: hitung TP/FP/FN/TN per tool dan kategori via compute_confusion.py; klasifikasi tidak diubah; 29 kasus error/unsupported didaftar |
| 2026-11-11 22:14 | E001-W1..E004-W1 | replication_stability_testing | 03_WORKING_COPY | 04_REGIPY_OUTPUT/{R1-R3}; 05_PYREG_OUTPUT/{R1-R3}; 06_RAW_RESULTS/replication_run_log.csv | input 66/66 matches baseline; `replication_run_log.csv` sha256=`e1d31f94d767c97cd39da817cec78ba8a46993f6a17c54ff9375dd59f0246565`; `output_json_sha256.txt` sha256=`44589cd22cf65eef9e398a54914a402891f1b835bac524a5f52996d8dbfc2038`; `reproducibility_summary.csv` sha256=`b5f9943e374e51c3b2c2a20d583bb1d9933764798fa4592b48bfc4ef0088a769` | Bintang Fajar | Week 7 Langkah 7: 3x replication (R1-R3) across 11 hives x 2 tools (66 runs); verified input hash stability against baseline (66/66 match); verified output reproducibility (100% deterministic text & canonical JSON); logged runtimes and consistent crash tracebacks for corrupted hives |
| 2026-11-11 22:18 | E001-W1..E004-W1 | comparative_disagreement_failure_analysis | 07_ANALYSIS/confusion_counts.csv; 06_RAW_RESULTS/replication_run_log.csv | 07_ANALYSIS/f1_per_category.csv; 07_ANALYSIS/disagreement_matrix.csv; 07_ANALYSIS/qualitative_failure_cases.csv; 07_ANALYSIS/QUALITATIVE_FAILURE_ANALYSIS.md | `f1_per_category.csv` sha256=`54bac6ca866af1f459d30de45c4aa95f5ac7c864dbdf4d4928edfd1d9848ce41`; `disagreement_matrix.csv` sha256=`eee1dd14b50ed6c3e214c7c394d7928d26913874102f69435c85afe733b95efc`; `qualitative_failure_cases.csv` sha256=`283b15d4be51eb29fbe7adcaaa906d5729428b79ddeab198f998c5c8c4200f1b`; `QUALITATIVE_FAILURE_ANALYSIS.md` sha256=`8aa7e26d355d1075d92f1cf5c239e6d3df64308d14fff08718e878b5c6d51d66` | Bintang Fajar | Week 7-8 Langkah 8: generated category F1 table with runtime stats; cross-tabulated 4x4 disagreement matrix; conducted in-depth qualitative analysis on 12 failure cases across 7 modalities; established bounded conclusions per 8.4 |

---

## 4. Format Machine-Readable (CSV)

File CSV resmi disimpan langsung di direktori yang sama:
- `02_GROUND_TRUTH/evidence_manifest.csv`
- `02_GROUND_TRUTH/chain_of_custody.csv`

