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

---

## 4. Format Machine-Readable (CSV)

File CSV resmi disimpan langsung di direktori yang sama:
- `02_GROUND_TRUTH/evidence_manifest.csv`
- `02_GROUND_TRUTH/chain_of_custody.csv`

