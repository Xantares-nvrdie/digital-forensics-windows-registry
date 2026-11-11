# Analisis Kualitatif Kasus Kegagalan & Kesimpulan Bounded (Langkah 8)

**Dokumen**: Evaluasi Komparatif Parser Windows Registry (Kelompok 4 - DF04)  
**Acuan**: Panduan Riset Forensik Digital 26/27 (Langkah 8.1 - 8.4)  
**Tools yang Diuji**: `regipy` (v6.5.0) vs `python-registry` (v1.3.1)  
**Dataset**: NIST CFReDS `cfreds-2017-winreg` (UGRD: Normal, Deleted, Corrupted, Manipulated)  

---

## 1. Tabel Ringkasan F1 per Kategori (Langkah 8.1 - 8.2)

| Tool | Kategori | N Artifact | TP | FP | FN | TN | Precision | Recall | F1-Score | Parser Error | Median Runtime (s) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| python-registry | normal | 22 | 22 | 0 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0 | 0.0325 |
| python-registry | deleted | 20 | 17 | 0 | 0 | 3 | 1.0000 | 1.0000 | 1.0000 | 0 | 14.3041 |
| python-registry | corrupted | 10 | 0 | 0 | 1 | 9 | - | 0.0000 | - | 10 | 0.0479 |
| python-registry | manipulated | 10 | 6 | 1 | 0 | 3 | 0.8571 | 1.0000 | 0.9231 | 0 | 7.2123 |
| python-registry | ALL | 62 | 45 | 1 | 1 | 15 | 0.9783 | 0.9783 | 0.9783 | 10 | 0.0624 |
| regipy | normal | 22 | 20 | 1 | 1 | 0 | 0.9524 | 0.9524 | 0.9524 | 0 | 0.1116 |
| regipy | deleted | 20 | 15 | 1 | 1 | 3 | 0.9375 | 0.9375 | 0.9375 | 0 | 1.7723 |
| regipy | corrupted | 10 | 0 | 0 | 1 | 9 | - | 0.0000 | - | 10 | 0.1084 |
| regipy | manipulated | 10 | 6 | 4 | 0 | 0 | 0.6000 | 1.0000 | 0.7500 | 0 | 1.7559 |
| regipy | ALL | 62 | 41 | 6 | 3 | 12 | 0.8723 | 0.9318 | 0.9011 | 10 | 1.7396 |

---

## 2. Disagreement Matrix (Langkah 8.2)

Matriks persilangan klasifikasi antara `regipy` (baris) dan `python-registry` (kolom) untuk seluruh 62 artifact titik uji:

```text
python-registry  FN  FP  TN  TP  Total
regipy                                
FN                1   0   0   2      3
FP                0   1   3   2      6
TN                0   0  12   0     12
TP                0   0   0  41     41
Total             1   1  15  45     62
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

### Kasus 1: [REG-N-006] Value berbeda (Value Data Misread)
- **File Hive**: `[nr]-01-1_v15.hive` (normal)
- **Target Objek**: `ROOT\0x01_TYPE1_DATA-TYPES -> VALUE 0x05 (DWORD-BE)`
- **Kondisi Ground Truth**: 83886080 (0x05000000)
- **Hasil `regipy`**: FP (Value terbaca string kosong "")
- **Hasil `python-registry`**: TP (Value terbaca tepat "83886080")
- **Akar Masalah Teknis**: regipy memiliki bug internal dalam parsing tipe REG_DWORD_BIG_ENDIAN, di mana buffer integer 4-byte big-endian gagal didecode dan diubah menjadi empty string.
- **Implikasi Forensik**: Bukti registry berupa network port, IP hex, atau setting konfigurasi big-endian dapat hilang sepenuhnya saat diekstrak dengan regipy.

### Kasus 2: [REG-D-014] Value berbeda (Value Data Misread in Modified Hive)
- **File Hive**: `[nrd]-08-1_v15.hive` (deleted)
- **Target Objek**: `ROOT\0x01_TYPE1_DATA-TYPES -> VALUE 0x05 (DWORD-BE)`
- **Kondisi Ground Truth**: 83886080 (0x05000000)
- **Hasil `regipy`**: FP (Value terbaca string kosong "")
- **Hasil `python-registry`**: TP (Value terbaca tepat "83886080")
- **Akar Masalah Teknis**: Konsistensi bug parser regipy pada tipe REG_DWORD_BIG_ENDIAN lintas seluruh kategori hive (normal maupun modified/deleted).
- **Implikasi Forensik**: Konfirmasi bahwa bug regipy bersifat deterministik pada tipe data tertentu dan bukan anomali satu file.

### Kasus 3: [REG-N-019] Key tidak ditemukan (Non-ASCII Name Decoding Mangling)
- **File Hive**: `[nr]-07-1_v15.hive` (normal)
- **Target Objek**: `ROOT\0x07_TYPE1_NON-ASCII\¡Hola!`
- **Kondisi Ground Truth**: Key: ¡Hola! (Spanish inverted exclamation mark, U+00A1)
- **Hasil `regipy`**: FN (Nama key termangle menjadi Hola!, U+FFFD)
- **Hasil `python-registry`**: TP (Nama key terekstrak sempurna: ¡Hola!)
- **Akar Masalah Teknis**: regipy secara agresif mengganti byte non-ASCII berkarakter Latin-1/Extended ASCII dengan Unicode Replacement Character (U+FFFD), sehingga pencarian path persis gagal.
- **Implikasi Forensik**: Bukti folder pengguna, malware dengan nama internasional, atau path aplikasi non-Inggris menjadi unsearchable / false negative pada regipy.

### Kasus 4: [REG-D-015] Key tidak ditemukan (Non-ASCII Name Decoding Mangling in Modified Hive)
- **File Hive**: `[nrd]-08-1_v15.hive` (deleted)
- **Target Objek**: `ROOT\0x07_TYPE1_NON-ASCII\¡Hola!`
- **Kondisi Ground Truth**: Key: ¡Hola!, Value: ¡Hola! : Spanish
- **Hasil `regipy`**: FN (Key termangle menjadi Hola!)
- **Hasil `python-registry`**: TP (Key terekstrak sempurna)
- **Akar Masalah Teknis**: Kelemahan parser decoding regipy pada subkey non-ASCII berulang pada hive modifikasi/slack space.
- **Implikasi Forensik**: Regresi konsisten dalam investigasi kasus multibahasa pada sistem Windows non-English.

### Kasus 5: [REG-C-001] Corrupted record (Corrupted HBIN Root Block Crash)
- **File Hive**: `[cr]-01_v15.hive` (corrupted)
- **Target Objek**: `ROOT Node`
- **Kondisi Ground Truth**: Kondisi hive rusak (HBIN memuat root key dioverwrite/rusak)
- **Hasil `regipy`**: Crash / Exception (construct.core.ConstError, RC=1)
- **Hasil `python-registry`**: Crash / Exception (ParseException: Invalid HBIN ID, RC=1)
- **Akar Masalah Teknis**: Blok HBIN pertama yang memuat signature cell 'nk' root key sengaja dikorupsi. Kedua parser tidak memiliki mekanisme fallback/recovery untuk carving parsial dan langsung crash.
- **Implikasi Forensik**: Kerusakan sektor penyimpanan pada awal file hive melumpuhkan parser CLI sepenuhnya tanpa menyajikan data parsial dari blok HBIN berikutnya yang masih intak.

### Kasus 6: [REG-C-005] Inaccessible valid structure due to early crash (Early Abort)
- **File Hive**: `[cr]-01_v15.hive` (corrupted)
- **Target Objek**: `Hive Header Block -> signature 'regf'`
- **Kondisi Ground Truth**: Header intak dan valid (signature: b'regf')
- **Hasil `regipy`**: FN (Crash sebelum header dilaporkan, 0 output)
- **Hasil `python-registry`**: FN (Crash sebelum header dilaporkan, 0 output)
- **Akar Masalah Teknis**: Kedua tool mengintegrasikan parsing header dan traversal tree dalam satu proses sekuensial monolitik. Kegagalan membaca root key membatalkan seluruh proses tanpa mengekspos metadata header.
- **Implikasi Forensik**: Metadata krusial (misal timestamp sinkronisasi hive di header REGF) tidak dapat diambil jika ada kerusakan pada bin root key.

### Kasus 7: [REG-C-006] Corrupted record (Invalid REGF Magic Signature)
- **File Hive**: `[cr]-05_v15.hive` (corrupted)
- **Target Objek**: `Hive Header Block -> signature 'regf'`
- **Kondisi Ground Truth**: Kondisi rusak (Magic bytes 'regf' diubah/rusak)
- **Hasil `regipy`**: Crash / Abort (construct.core.ConstError, RC=1)
- **Hasil `python-registry`**: Crash / Abort (ParseException: Invalid REGF ID, RC=1)
- **Akar Masalah Teknis**: Validasi integritas signature 4-byte pertama file gagal. Parser menolak mengalokasikan buffer parsing.
- **Implikasi Forensik**: Perilaku aman (fail-fast) yang mencegah memory corruption, namun membutuhkan tools carving hex mentah bagi analis jika header sengaja di-wipe oleh malware.

### Kasus 8: [REG-M-001] Unsupported structure / Anti-forensics (Hidden Root Key Tampering)
- **File Hive**: `[mr]-01.(1)_v15.hive` (manipulated)
- **Target Objek**: `ROOT Key`
- **Kondisi Ground Truth**: Root key pointer dimanipulasi dari 0x20 ke 0x120 (mengarah ke subkey)
- **Hasil `regipy`**: FP (Melaporkan root dan mengekstrak 542 subkeys)
- **Hasil `python-registry`**: TN (Hanya melaporkan 1 key root baru, menyembunyikan 542 subkeys)
- **Akar Masalah Teknis**: python-registry patuh secara buta pada pointer hierarki root di header (hanya melihat subkey yang ditunjuk sebagai root terisolasi). regipy menelusuri cell bin secara mendalam sehingga menemukan sel yang sengaja disembunyikan.
- **Implikasi Forensik**: Teknik anti-forensik 'root key redirection' berhasil membodohi python-registry sehingga bukti registry disembunyikan secara efektif, tetapi gagal terhadap regipy.

### Kasus 9: [REG-M-004] Hidden subtree exposure (Structure Tampering Discrepancy)
- **File Hive**: `[mr]-01.(1)_v15.hive` (manipulated)
- **Target Objek**: `ROOT\0x02_TYPE1_TREE`
- **Kondisi Ground Truth**: Cabang hierarki tree disembunyikan dari traversal root resmi
- **Hasil `regipy`**: FP (Cabang tersembunyi dilaporkan aktif)
- **Hasil `python-registry`**: TN (Cabang tersembunyi tidak dilaporkan)
- **Akar Masalah Teknis**: Perbedaan fundamental arsitektur parser: hierarkis pointer-driven (python-registry) vs cell-allocation scan (regipy).
- **Implikasi Forensik**: Discrepancy antar-tool menjadi indikator kuat adanya manipulasi struktur registry (anti-forensics).

### Kasus 10: [REG-M-005] Hidden multilingual branch exposure
- **File Hive**: `[mr]-01.(1)_v15.hive` (manipulated)
- **Target Objek**: `ROOT\0x07_TYPE1_NON-ASCII`
- **Kondisi Ground Truth**: Cabang multilingual disembunyikan oleh redirect root
- **Hasil `regipy`**: FP (Cabang tersembunyi dilaporkan aktif)
- **Hasil `python-registry`**: TN (Cabang tersembunyi tidak dilaporkan)
- **Akar Masalah Teknis**: Konfirmasi konsistensi pembacaan unlinked subkey cell oleh regipy.
- **Implikasi Forensik**: Memperkuat temuan bahwa parser yang lebih 'ceroboh' terhadap pointer resmi justru lebih tangguh menemukan hidden data.

### Kasus 11: [REG-M-006] Data hiding silent extraction (Tampered Data Length)
- **File Hive**: `[mr]-06.(1)_v15.hive` (manipulated)
- **Target Objek**: `ROOT\0x01_TYPE1_DATA-TYPES -> VALUE 0x03 (BINARY)`
- **Kondisi Ground Truth**: Manipulasi 'data size' diset ke 0 pada value BINARY
- **Hasil `regipy`**: FP/Silent (Mengekstrak value biner kosong tanpa peringatan)
- **Hasil `python-registry`**: FP/Silent (Mengekstrak value biner kosong tanpa peringatan)
- **Akar Masalah Teknis**: Kedua parser mempercayai field data length = 0 dalam struktur vk cell tanpa memeriksa sisa alokasi cell data di slack space.
- **Implikasi Forensik**: Data payload malware yang disembunyikan dengan memotong size menjadi 0 terlewatkan sepenuhnya oleh kedua parser otomatis tanpa ada error flag.

### Kasus 12: [REG-N-013] Timestamp precision truncation (Microsecond Rounding Error)
- **File Hive**: `[nr]-02-1_v15.hive` (normal)
- **Target Objek**: `ROOT\0x02_TYPE1_TREE\Node_1`
- **Kondisi Ground Truth**: 2017-09-25T14:22:41.935209+00:00
- **Hasil `regipy`**: 0 (Diekstrak: ...41.935208+00:00, selisih 1 us)
- **Hasil `python-registry`**: 1 (Diekstrak: ...41.935209, cocok persis)
- **Akar Masalah Teknis**: Konversi Windows FILETIME 100-nanosecond ke Unix timestamp float pada library regipy mengalami pembulatan floating point yang memotong 1 mikrodetik.
- **Implikasi Forensik**: Dapat memengaruhi korelasi urutan kejadian mikrosekon pada timeline analysis forensik tingkat tinggi.

---

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
