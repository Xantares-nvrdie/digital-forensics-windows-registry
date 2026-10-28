# Dokumen Desain Eksperimen & Pre-Registration (Minggu 2)
**Kelompok 4 (DF04): Windows Registry Forensics Menggunakan Reference Dataset**  
**Dataset Utama**: NIST CFReDS Windows Registry Reference Dataset (`cfreds-2017-winreg` - UGRD)  
**Tools yang Diuji**:
- **Parser A**: `regipy` (v6.5.0)
- **Parser B**: `python-registry` (v1.3.1)
- **Analisis & Evaluasi**: `pandas` (v3.1.0)

---

## 1. Research Questions & Tujuan Riset

Eksperimen ini dirancang sebagai pengujian komparatif deterministik dan stabilitas dua parser Windows Registry independen terhadap ground truth standar NIST.

* **RQ1 (Akurasi Ekstraksi Dasar)**:  
  *Seberapa tepat kedua parser mengekstrak key path, value name, value data, dan timestamp last-written dari reference Registry hives?*
* **RQ2 (Ketahanan Tipe & Struktur Artifact)**:  
  *Artifact type apa yang paling sering memicu inkonsistensi (misal: Unicode/non-ASCII characters, large binary data, atau deep tree structure)?*
* **RQ3 (Resiliensi terhadap Anomali Struktur)**:  
  *Bagaimana kondisi hive yang corrupted (damaged header/bin) atau manipulated (tampered pointer/offset) memengaruhi perilaku parser (apakah graceful error/partial extraction atau unhandled exception/crash)?*

---

## 2. Experimental Matrix (Matriks Skenario Eksperimen)

Sesuai ketentuan Bagian 6.E dan Quality Gate Bagian H pada panduan modul, eksperimen mencakup minimal 3 kategori hive dengan minimal 60 titik uji (*artifact test points*).

### 2.1 Ringkasan Alokasi Sampel

| Kondisi Hive | Sub-Koleksi Dataset | Jumlah Kasus (Hive) | Alokasi Artifact Ground Truth | Parser yang Diuji | Replikasi | Total Run Evaluasi |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Normal Registry** | `ugrd-nr` | 3 | **22 artifacts** | `regipy` + `python-registry` | 3x (R1, R2, R3) | 22 × 2 × 3 = 132 |
| **Deleted Records** | `ugrd-nrd` | 4 | **20 artifacts** | `regipy` + `python-registry` | 3x (R1, R2, R3) | 20 × 2 × 3 = 120 |
| **Corrupted Hives** | `ugrd-cr` | 2 | **10 artifacts** | `regipy` + `python-registry` | 3x (R1, R2, R3) | 10 × 2 × 3 = 60 |
| **Manipulated Hives**| `ugrd-mr` | 2 | **10 artifacts** | `regipy` + `python-registry` | 3x (R1, R2, R3) | 10 × 2 × 3 = 60 |
| **TOTAL** | **4 Kategori** | **11 Hives** | **62 Artifacts** | **2 Tools** | **3 Runs** | **372 Observasi** |

---

### 2.2 Rincian Skenario Kasus Uji

Format penamaan kasus mengikuti aturan Bagian 3.2: `DF04-<kategori>-<no_kasus>-R<replikasi>`.

| Case ID Prefix | Kategori | File Hive Sumber | Karakteristik Skenario | Rentang ID Artifact | Target Evaluasi Utama |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `DF04-NR-01` | Normal | `[nr]-01-1_v15.hive` | Multi-data types (SZ, EXP_SZ, BIN, DWORD, MULTI_SZ, dll.) | `REG-N-001` s/d `REG-N-012` | Integritas konversi tipe data Registry |
| `DF04-NR-02` | Normal | `[nr]-02-1_v15.hive` | Hierarki tree berjenjang (`Node_1`, `Node_1-1`, `Node_2`, dll.) | `REG-N-013` s/d `REG-N-017` | Ketepatan rekursi path & timestamp |
| `DF04-NR-03` | Normal | `[nr]-07-1_v15.hive` | Non-ASCII multilingual Unicode (Spanyol, Rusia, Jepang, Mandarin) | `REG-N-018` s/d `REG-N-022` | Konsistensi decoding UTF-16LE / UTF-8 |
| `DF04-NRD-01`| Deleted | `[nrd]-01-1_v15.hive` | Penghapusan key yang memiliki value tetapi tanpa subkey | `REG-D-001` s/d `REG-D-005` | Deteksi unallocated cell vs active enumeration |
| `DF04-NRD-02`| Deleted | `[nrd]-04-1_v15.hive` | Penghapusan satu value besar (16.383 char) di dalam subkey aktif | `REG-D-006` s/d `REG-D-010` | Isolasi value deleted tanpa merusak subkey |
| `DF04-NRD-03`| Deleted | `[nrd]-08-1_v15.hive` | Pengubahan ukuran data menjadi lebih kecil (residual slack space) | `REG-D-011` s/d `REG-D-015` | Pembacaan modified data vs unallocated slack |
| `DF04-NRD-04`| Deleted | `[nrd]-14-1_v15.hive` | Pengubahan nama value dengan ukuran alokasi tetap sama | `REG-D-016` s/d `REG-D-020` | Resolusi nama value ter-update |
| `DF04-CR-01` | Corrupted | `[cr]-01_v15.hive` | Kerusakan fisik pada hive bin (`hbin`) yang memuat root key | `REG-C-001` s/d `REG-C-005` | Penanganan invalid HBIN pointer |
| `DF04-CR-02` | Corrupted | `[cr]-05_v15.hive` | Kerusakan header file (`regf` magic signature rusak) | `REG-C-006` s/d `REG-C-010` | Validasi awal header integrity |
| `DF04-MR-01` | Manipulated | `[mr]-01.(1)_v15.hive` | Manipulasi offset root key (disamarkan mengarah ke subkey) | `REG-M-001` s/d `REG-M-005` | Deteksi struktur sembunyi (hidden branches) |
| `DF04-MR-02` | Manipulated | `[mr]-06.(1)_v15.hive` | Manipulasi offset data value ke lokasi non-aktif/invalid | `REG-M-006` s/d `REG-M-010` | Error handling invalid data pointers |

---

## 3. Data Dictionary (Kamus Data)

Struktur data diimplementasikan dalam 2 skema CSV standar:
1. `02_GROUND_TRUTH/registry_expected.csv` (Katalog target pengujian)
2. `07_ANALYSIS/registry_item_results.csv` (Hasil pencatatan item-level eksperimen)

### 3.1 Kamus Data: `02_GROUND_TRUTH/registry_expected.csv`

| Field | Tipe Data | Nullable | Definisi & Makna | Contoh Nilai |
| :--- | :--- | :---: | :--- | :--- |
| `artifact_id` | String | NO | Identifier unik titik uji sesuai format preregistered. | `REG-N-001`, `REG-D-006` |
| `category` | Enum | NO | Kategori hive: `normal`, `deleted`, `corrupted`, `manipulated`. | `normal` |
| `hive_file` | String | NO | Nama file hive sumber di dalam working copy. | `[nr]-01-1_v15.hive` |
| `key_path` | String | NO | Registry key path absolut dari root. | `ROOT\0x01_TYPE1_DATA-TYPES` |
| `value_name` | String | YES | Nama value target (berisi `NA` jika level uji adalah key). | `VALUE 0x01 (SZ)` |
| `expected_value` | String | YES | Nilai data yang diharapkan menurut ground truth NIST. | `UTF-16LE NULL-terminated string` |
| `expected_timestamp` | String/ISO | YES | Timestamp last written dalam format ISO-8601 UTC (`NA` jika tidak terdokumentasi). | `2017-09-25T14:22:40.249934` |
| `expected_status` | Enum | NO | Status artifact pada hive: `ACTIVE`, `DELETED`, `MODIFIED`, `CORRUPTED`, `MANIPULATED`. | `ACTIVE` |
| `source_reference` | String | NO | Referensi dokumen sumber teknis. | `NIST CFReDS UGRD-NR` |
| `notes` | String | YES | Catatan teknis pengujian artifact. | `RegSZ string extraction` |

---

### 3.2 Kamus Data: `07_ANALYSIS/registry_item_results.csv` & Master CSV
Sesuai Bagian G (Hal. 9) dan Bagian 8.1 (Hal. 10) panduan modul:

| Field | Tipe Data | Nullable | Definisi & Makna | Contoh Nilai |
| :--- | :--- | :---: | :--- | :--- |
| `case_id` | String | NO | Kode unik run pengujian (`DF04-<kode>-<no>-R<rep>`). | `DF04-NR-01-R1` |
| `dataset_category` | Enum | NO | Kategori dataset: `normal`, `deleted`, `corrupted`, `manipulated`. | `normal` |
| `hive` | String | NO | Nama file hive yang diproses. | `[nr]-01-1_v15.hive` |
| `artifact_id` | String | NO | ID titik uji merujuk ke `registry_expected.csv`. | `REG-N-001` |
| `expected_key` | String | NO | Path key menurut ground truth. | `ROOT\0x01_TYPE1_DATA-TYPES` |
| `expected_value` | String | YES | Nilai value menurut ground truth. | `b'none'` |
| `tool` | String | NO | Nama dan versi parser yang dievaluasi. | `regipy v6.5.0` |
| `detected_key` | String | YES | Path key yang berhasil diekstrak parser (`NA` jika tidak ditemukan). | `ROOT\0x01_TYPE1_DATA-TYPES` |
| `detected_value` | String | YES | Nilai value yang berhasil diekstrak parser (`NA` jika tidak ditemukan). | `b'none'` |
| `timestamp_match` | Integer | NO | Biner `1` jika timestamp cocok setelah normalisasi UTC, `0` jika berbeda / tidak ditemukan. | `1` |
| `tp` | Integer | NO | `1` jika memenuhi kriteria True Positive, selainnya `0`. | `1` |
| `fp` | Integer | NO | `1` jika memenuhi kriteria False Positive, selainnya `0`. | `0` |
| `fn` | Integer | NO | `1` jika memenuhi kriteria False Negative, selainnya `0`. | `0` |
| `runtime_sec` | Float | NO | Waktu eksekusi proses parsing file hive bersangkutan (detik). | `0.0421` |
| `sha256_before` | String | NO | Hash SHA-256 file input working copy sebelum pemrosesan. | `b2f4...` |
| `parser_error` | String | YES | Traceback/pesan exception jika parser gagal memproses; kosong jika sukses. | `RegistryParse.ParseException` |
| `notes` | String | YES | Catatan observasi spesifik analis. | `Exact match on bytes` |

---

## 4. Pre-Registration Ringkas (Bab 7.1)

Sebelum melakukan ekstraksi massal di Minggu 3 dan seterusnya, kriteria pengujian berikut **dikunci secara preregistered**:

### 4.1 Definisi Operasional Metrik Klasifikasi

1. **True Positive (TP)**:
   - Berlaku untuk target berstatus `expected_status == 'ACTIVE'`.
   - `detected_key` cocok persis (case-insensitive setelah normalisasi separator `\`) dengan `expected_key`.
   - Jika `value_name` diuji, `detected_value` harus cocok semantik dengan `expected_value`.
2. **False Negative (FN)**:
   - Target berstatus `expected_status == 'ACTIVE'`, tetapi:
     - Parser tidak memuat key/value bersangkutan pada output JSON, ATAU
     - Parser melempar *unhandled exception* (crash) sebelum mencapai objek tersebut.
3. **False Positive (FP)**:
   - Parser melaporkan suatu objek sebagai *active key/value* padahal ground truth mendokumentasikan objek tersebut berstatus `DELETED` atau `CORRUPTED`, ATAU
   - Parser mengekstrak objek tetapi nilainya terkorupsi / salah mapping ke cell lain.
4. **True Negative (TN)**:
   - Objek berstatus `DELETED` / `CORRUPTED`, dan parser standar memang tidak melaporkannya sebagai active key (karena parser standar hanya membaca alokasi aktif).

---

### 4.2 Rumus Perhitungan Metrik

* **Precision**:
  ```text
  Precision = TP / (TP + FP)
  ```
  *(Proporsi temuan yang benar dari seluruh temuan parser).*

* **Recall**:
  ```text
  Recall = TP / (TP + FN)
  ```
  *(Proporsi target ground truth yang berhasil ditemukan).*

* **F1-Score**:
  ```text
  F1-Score = 2 × (Precision × Recall) / (Precision + Recall)
  ```
  *(Rata-rata harmonik keseimbangan precision dan recall).*

* **Timestamp Error**:
  ```text
  Timestamp Error = |Timestamp_tool - Timestamp_ground_truth|
  ```
  *(Normalisasi dilakukan dengan mengonversi semua string timestamp ke timezone UTC dan menghitung deviasi dalam detik).*

* **Reproducibility Rate**:
  ```text
  Reproducibility Rate = Total Run Output Identik / Total Run
  ```

---

### 4.3 Kriteria Excluded & Failed Run (Preregistered Rule)

1. **Larangan Menghapus Run**:
   - Jika parser mengalami *crash*, *hang*, atau *traceback error* (khususnya pada `[cr]-*` dan `[mr]-*`), proses run **DILARANG DIHAPUS**.
2. **Pencatatan Kegagalan**:
   - Traceback dicatat lengkap pada kolom `parser_error` dan file log `06_RAW_RESULTS/`.
   - Kasus tersebut diklasifikasikan sebagai failure case yang akan dibahas pada bab *Discussion & Failure Analysis* mini-paper.
3. **Replikasi & Uji Reproducibility**:
   - Setiap run diulang sebanyak 3 kali (R1, R2, R3) dengan hash input yang diverifikasi identik (`sha256_before`).
   - Hash file output JSON (`sha256_after`) dicatat untuk menghitung **Reproducibility Rate** (`Jumlah Run Identik / Total Run`).

