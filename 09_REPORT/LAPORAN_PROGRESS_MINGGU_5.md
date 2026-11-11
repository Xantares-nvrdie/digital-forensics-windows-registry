# Laporan Progress Minggu 5 — DF04 Kelompok 4

**Topik**: Windows Registry Forensics Menggunakan Reference Dataset (NIST CFReDS `cfreds-2017-winreg`, UGRD)
**Operator**: Bintang Fajar Putra Pamungkas (2405073) & Shidqi Rasyad Firjatulah (2408156)
**Fokus Minggu 5** (jadwal modul): eksperimen utama tahap 2, target ≥75% kasus selesai + raw CSV
**Cakupan teknis**: modul Langkah 5 (bandingkan key path, value, timestamp, status terhadap ground truth)
**Tool**: `regipy` 6.5.0, `python-registry` 1.3.1, Python 3.13, pandas

> Semua angka di laporan ini berasal dari satu run (R1) pada 11 hive dan 62 artifact. Replikasi R2/R3 belum dikerjakan. Angka metrik bersifat awal dan hanya berlaku untuk hive dan artifact yang diuji.

---

## 1. Ringkasan Status

| Item | Target modul | Status |
| :--- | :--- | :---: |
| Hive yang diekstrak oleh kedua parser | 11 hive | 11/11 (2 hive corrupted crash, log tersimpan) |
| Artifact test point yang dievaluasi | ≥60 (quality gate), ≥75% kasus Minggu 5 | 62/62 (100%) |
| Raw CSV item-level | `registry_item_results.csv`, 2 baris per artifact | 124 baris |
| Raw output asli kedua tool + log | wajib | JSON + log di `04_`, `05_`, `06_` |
| Error parser dilaporkan, tidak disembunyikan | wajib | Ya (kolom `parser_error` + `06_RAW_RESULTS/`) |
| Replikasi R1–R3 | Minggu 6 | **Baru R1** |
| `confusion_counts.csv` dan tabel F1 final (Langkah 6, 8) | Minggu 6–7 | Belum |
| Visualisasi (min. 4) | Minggu 7 | Belum |

Gerbang ≥75% untuk Minggu 5 terpenuhi: seluruh matriks eksperimen (11 hive, 62 artifact, 2 tool) sudah dijalankan satu kali. Dari 372 observasi yang direncanakan (62 × 2 × 3 replikasi), 124 selesai (R1). Replikasi untuk uji reproducibility dijadwalkan di Minggu 6.

---

## 2. Pekerjaan Minggu Ini

1. **Ekstraksi python-registry dan regipy pada 11 hive** (lihat laporan Minggu 4). Hive `[cr]-01` dan `[cr]-05` gagal pada kedua parser. Traceback python-registry: `Invalid HBIN ID` dan `Invalid REGF ID`. Traceback regipy: `construct.core.ConstError`. Log regipy untuk kedua hive ditambahkan minggu ini di `06_RAW_RESULTS/[cr]-0{1,5}_v15_regipy_run.txt`.
2. **Evaluasi terhadap ground truth** dengan [`07_ANALYSIS/evaluate_artifacts.py`](file:///Users/Xantares/WORKZEN/Digital%20Forensics/DF04_Kelompok4/07_ANALYSIS/evaluate_artifacts.py). Script menghasilkan [`registry_item_results.csv`](file:///Users/Xantares/WORKZEN/Digital%20Forensics/DF04_Kelompok4/07_ANALYSIS/registry_item_results.csv) dan [`tool_disagreement.csv`](file:///Users/Xantares/WORKZEN/Digital%20Forensics/DF04_Kelompok4/07_ANALYSIS/tool_disagreement.csv).
3. **Urutan sesuai modul 5.4**: tiap tool dinilai ke ground truth sendiri-sendiri, baru kemudian dibandingkan antar tool.

### Aturan klasifikasi (dari preregistration, diterapkan mekanis)

| Status ground truth | Hasil parser | Klasifikasi |
| :--- | :--- | :---: |
| ACTIVE / MODIFIED | key dan value cocok | TP |
| ACTIVE / MODIFIED | key ada, value berbeda | FP |
| ACTIVE / MODIFIED | key atau value hilang, atau parser crash | FN |
| DELETED / CORRUPTED / MANIPULATED | dilaporkan sebagai aktif | FP |
| DELETED / CORRUPTED / MANIPULATED | tidak dilaporkan, atau parser exception | TN |

Normalisasi pencocokan: path dibandingkan tanpa beda huruf besar-kecil dan dalam bentuk Unicode NFC. Value dicocokkan lintas representasi (bytes, hex, string UTF-16, list tanpa string kosong di ujung). Timestamp dikonversi ke UTC lalu dibandingkan persis; selisih dicatat di `notes`. Kolom yang tidak berlaku diisi `NA`.

---

## 3. Hasil Awal (R1)

### 3.1 Jumlah klasifikasi per tool dan kategori

| Tool | Kategori | TP | FP | FN | TN |
| :--- | :--- | :-: | :-: | :-: | :-: |
| python-registry | normal | 22 | 0 | 0 | 0 |
| python-registry | deleted | 17 | 0 | 0 | 3 |
| python-registry | corrupted | 0 | 0 | 1 | 9 |
| python-registry | manipulated | 6 | 1 | 0 | 3 |
| regipy | normal | 20 | 1 | 1 | 0 |
| regipy | deleted | 15 | 1 | 1 | 3 |
| regipy | corrupted | 0 | 0 | 1 | 9 |
| regipy | manipulated | 6 | 4 | 0 | 0 |

### 3.2 Precision / Recall / F1 awal

| Tool | TP | FP | FN | TN | Precision | Recall | F1 |
| :--- | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| python-registry | 45 | 1 | 1 | 15 | 0.978 | 0.978 | 0.978 |
| regipy | 41 | 6 | 3 | 12 | 0.872 | 0.932 | 0.901 |

Untuk kategori corrupted, TP dan FP keduanya 0 sehingga Precision dan F1 tidak terdefinisi; hanya Recall (0) dan jumlah TN yang bermakna. Selisih di atas berasal dari beberapa artifact tertentu (bagian 3.3), bukan dari perbedaan menyeluruh. Dengan 62 artifact dan satu run, angka ini belum cukup untuk menyatakan salah satu tool lebih baik secara umum.

### 3.3 Perbedaan klasifikasi antar tool (7 dari 62 artifact)

| Artifact | Hive | regipy | python-registry | Penyebab yang teramati |
| :--- | :--- | :-: | :-: | :--- |
| REG-N-006 | `[nr]-01-1` | FP | TP | regipy mengembalikan string kosong untuk `REG_DWORD_BIG_ENDIAN`; python-registry mengembalikan 83886080 |
| REG-D-014 | `[nrd]-08-1` | FP | TP | gejala sama dengan N-006 |
| REG-N-019 | `[nr]-07-1` | FN | TP | nama key `¡Hola!` muncul di regipy sebagai `�Hola!` (karakter U+FFFD) |
| REG-D-015 | `[nrd]-08-1` | FN | TP | gejala sama dengan N-019 |
| REG-M-001 | `[mr]-01.(1)` | FP | TN | regipy melaporkan root; python-registry tidak melaporkan root asli |
| REG-M-004 | `[mr]-01.(1)` | FP | TN | regipy melaporkan subtree yang seharusnya tersembunyi |
| REG-M-005 | `[mr]-01.(1)` | FP | TN | sama dengan M-004 |

Dua tool sepakat pada 55 artifact lainnya.

### 3.4 Akurasi timestamp (metrik terpisah dari TP/FP/FN, sesuai modul 6.1)

| Kelompok | python-registry | regipy |
| :--- | :-: | :-: |
| Normal (22 titik) | 22/22 cocok | 12/22 cocok |
| Deleted (17 titik) | 7/17 | 7/17 |
| Manipulated (6 titik) | 0/6 | 0/6 |

- Pada hive normal, 10 dari 22 timestamp regipy berbeda tepat 1 µs dari ground truth (pembulatan). python-registry persis.
- Pada hive deleted dan manipulated, selisihnya sampai belasan detik dan **sama pada kedua tool** (maksimal beda 1 µs antar tool). Ini mengarah ke masalah di ground truth, bukan di parser (lihat 4.2).

---

## 4. Temuan Penting dan Catatan Kejujuran

### 4.1 `REG-M-006` menunjuk value yang salah
Ground truth menulis tampering pada `VALUE 0x01 (SZ)`. Hasil diff hive `[mr]-06.(1)` terhadap `[nr]-01-1` menunjukkan yang berubah adalah `VALUE 0x03 (BINARY)` (datanya menjadi kosong, tanpa error pada kedua parser). Ini sejalan dengan strategi "hide data of a value" di PDF NIST, yang menargetkan value bertipe BINARY. Akibatnya klasifikasi FP untuk `REG-M-006` pada kedua tool tidak mencerminkan perilaku parser. Ground truth **tidak saya ubah** karena sudah dikunci di preregistration; catatan ditaruh di kolom `notes`. Perlu keputusan kelompok soal amandemen resmi (dengan entri CoC) sebelum angka final.

### 4.2 Timestamp ground truth untuk hive deleted dan manipulated kemungkinan perkiraan
Nilai `expected_timestamp` tampak sama untuk seluruh artifact dalam satu hive, sedangkan timestamp key aktual berbeda-beda dan disepakati kedua parser. Perlu diverifikasi ke PDF NIST sebelum metrik timestamp dilaporkan di paper.

### 4.3 Hive manipulated `[mr]-01.(1)`
PDF NIST menjelaskan bahwa root cell offset diarahkan ke subkey pertama root asli. python-registry pun membaca `0x01_TYPE1_DATA-TYPES` sebagai root. regipy tetap menampilkan seluruh tree (543 record). Mengapa regipy bisa menemukan struktur yang disembunyikan belum diuji dan masih berupa hipotesis.

### 4.4 Hive corrupted
Kedua parser crash pada `[cr]-01` dan `[cr]-05`, jadi 18 dari 20 titik uji berstatus TN (parser berhenti dengan exception). Artifact `REG-C-005` (header `regf` yang masih valid pada `[cr]-01`) menjadi FN karena parser crash sebelum header dapat dibaca. Hal ini dihitung sesuai rule.

### 4.5 Perubahan terhadap file pilot Week 3
`registry_item_results.csv` buatan pilot (22 titik) ditimpa hasil evaluasi penuh. 13 dari 44 baris pilot berubah klasifikasi, terutama FN menjadi TN karena rule preregistration (objek DELETED/CORRUPTED yang memang tidak dilaporkan parser bukan kegagalan). Versi lama masih ada di riwayat Git.

---

## 5. Chain of Custody

Seluruh CoC tersimpan di `02_GROUND_TRUTH/` (`chain_of_custody.csv`, `CHAIN_OF_CUSTODY.md`, `evidence_manifest.csv`).

| Timestamp | Evidence | Action | Operator | Catatan |
| :--- | :--- | :--- | :--- | :--- |
| 2026-10-29 11:03 | E001-W1; E002-W1; E003-W1 | `pilot_extraction` | Shidqi Rasyad | Pilot Week 3 |
| 2026-11-11 21:28 | E001-W1..E004-W1 | `mass_cross_validation_extraction` | Bintang Fajar | Ekstraksi 11 hive, kedua parser |
| 2026-11-11 22:00 | E001-W1..E004-W1 | `ground_truth_comparison` | Bintang Fajar | Evaluasi 62 artifact × 2 tool, log regipy `[cr]` ditambahkan |

Prinsip yang dijaga: baseline tidak diubah, pemrosesan hanya pada working copy, failed run tidak dihapus. Keterbatasan: timestamp Week 1–3 direkonstruksi dari metadata filesystem dan Git, dan kolom `hash/verification` untuk Week 3–5 masih `match YES` tanpa hash eksplisit.

---

## 6. Risiko dan Keterbatasan

- Replikasi belum ada, sehingga reproducibility rate belum dapat dihitung.
- Sampel kecil (62 artifact, 11 hive UGRD) dan hanya dua parser; kesimpulan tidak boleh digeneralisasi ke Registry di dunia nyata.
- Dua masalah ground truth (4.1 dan 4.2) berpotensi mengubah angka manipulated dan metrik timestamp.
- Aturan pencocokan value (lintas representasi) adalah interpretasi saya atas "cocok semantik" di preregistration; sebaiknya kelompok mereview.

---

## 7. Rencana Minggu 6 (replikasi dan finalisasi data)

1. Putuskan amandemen ground truth `REG-M-006` dan verifikasi timestamp ke PDF NIST; catat di CoC.
2. Verifikasi SHA-256 working copy terhadap `baseline_sha256.txt` dan catat hasil eksplisitnya.
3. Jalankan R2 dan R3 pada seluruh hive dengan input hash identik; simpan SHA-256 output (`06_RAW_RESULTS/output_json_sha256.txt`) dan runtime tiap run.
4. Hitung `confusion_counts.csv` (Langkah 6) per tool dan kategori.
5. Siapkan data untuk Langkah 8: F1 per kategori, disagreement matrix, dan minimal 10 failure case untuk analisis kualitatif.

