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
| **Lingkungan Pengujian** | macOS (Darwin arm64) / Linux WSL |
| **Tools Hashing** | SHA-256 (`sha256sum` / `shasum -a 256` / `Get-FileHash`) |

---

## 2. Evidence Manifest (Standar Modul Bagian 8.2)

> **Ketentuan Pengisian (Bagian 4.2 & 8.2):**
> - Catat setiap file bukti digital segera setelah dibuat atau diunduh.
> - `evidence_id`: Berikan kode unik bukti (contoh: `E001`, `E002`, `E001-W1` untuk working copy dari `E001`).
> - `status`: Tuliskan `baseline` untuk master asli atau `working copy` untuk salinan operasional.

| evidence_id | filename | size_bytes | sha256 | source | created/downloaded_at | status |
| :--- | :--- | :---: | :--- | :--- | :---: | :---: |
| E001 | `01_BASELINE/cfreds-2017-winreg_ugrd-nr.7z` | | | NIST CFReDS Portal | YYYY-MM-DD HH:MM | baseline |
| E001-W1 | `03_WORKING_COPY/ugrd-nr/` | | | copy of E001 | YYYY-MM-DD HH:MM | working copy |
| E002 | `01_BASELINE/cfreds-2017-winreg_ugrd-nrd.7z` | | | NIST CFReDS Portal | YYYY-MM-DD HH:MM | baseline |
| E002-W1 | `03_WORKING_COPY/ugrd-nrd/` | | | copy of E002 | YYYY-MM-DD HH:MM | working copy |
| E003 | `01_BASELINE/cfreds-2017-winreg_ugrd-cr.7z` | | | NIST CFReDS Portal | YYYY-MM-DD HH:MM | baseline |
| E003-W1 | `03_WORKING_COPY/ugrd-cr/` | | | copy of E003 | YYYY-MM-DD HH:MM | working copy |
| E004 | `01_BASELINE/cfreds-2017-winreg_ugrd-mr.7z` | | | NIST CFReDS Portal | YYYY-MM-DD HH:MM | baseline |
| E004-W1 | `03_WORKING_COPY/ugrd-mr/` | | | copy of E004 | YYYY-MM-DD HH:MM | working copy |
| E005 | `02_GROUND_TRUTH/cfreds-2017-winreg.pdf` | | | NIST CFReDS Portal | YYYY-MM-DD HH:MM | baseline |

*(Tambahkan baris sesuai file bukti atau subset hive yang dianalisis)*

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
| YYYY-MM-DD HH:MM | E001 | download/create | source | 01_BASELINE | SHA-256 ... | [Nama Operator] | baseline archive downloaded |
| YYYY-MM-DD HH:MM | E001 | extract | 01_BASELINE | 01_BASELINE/ugrd-nr | match YES | [Nama Operator] | extracted without deleting archive |
| YYYY-MM-DD HH:MM | E001-W1 | copy | 01_BASELINE | 03_WORKING_COPY | match YES | [Nama Operator] | working copy created for analysis |
| YYYY-MM-DD HH:MM | E002 | download/create | source | 01_BASELINE | SHA-256 ... | [Nama Operator] | baseline archive downloaded |
| YYYY-MM-DD HH:MM | E002-W1 | copy | 01_BASELINE | 03_WORKING_COPY | match YES | [Nama Operator] | working copy created for analysis |
| YYYY-MM-DD HH:MM | E003 | download/create | source | 01_BASELINE | SHA-256 ... | [Nama Operator] | baseline archive downloaded |
| YYYY-MM-DD HH:MM | E003-W1 | copy | 01_BASELINE | 03_WORKING_COPY | match YES | [Nama Operator] | working copy created for analysis |
| YYYY-MM-DD HH:MM | E004 | download/create | source | 01_BASELINE | SHA-256 ... | [Nama Operator] | baseline archive downloaded |
| YYYY-MM-DD HH:MM | E004-W1 | copy | 01_BASELINE | 03_WORKING_COPY | match YES | [Nama Operator] | working copy created for analysis |
| YYYY-MM-DD HH:MM | E005 | download/create | source | 02_GROUND_TRUTH | SHA-256 ... | [Nama Operator] | ground truth specification PDF |

---

## 4. Format Machine-Readable (CSV)

Jika ingin disimpan atau diserahkan dalam format CSV terpisah:

### A. Header `evidence_manifest.csv` (Bagian 8.2)
```csv
evidence_id,filename,size_bytes,sha256,source,created/downloaded_at,status
```

### B. Header `chain_of_custody.csv` (Bagian 8.3)
```csv
timestamp,evidence_id,action,from,to,hash/verification,operator,notes
```
