# FARcontrol — Komparasi Bahasa Pemrograman (Keputusan Implementasi)

**Status:** Diterima (Accepted) — 2026-10-02
**Keputusan:** **Rust** (stable, edition 2021) untuk seluruh komponen v0.1.0 (daemon, CLI owner, CLI agent)
**Dirujuk oleh:** ADR-0001
**Pemutus:** Owner (mandat: "yang paling bagus, yang bener-bener bagus, wajib komparasi")

---

## 1. Ringkasan Eksekutif

FARcontrol adalah **daemon keamanan-kritis** yang:

1. menerima input **tidak-terpercaya dari jaringan** (request AI agent eksternal),
2. menjalankan **evaluasi otorisasi** sebelum setiap akses (authentication ≠ authorization),
3. mengeksekusi **perintah sistem** atas nama pihak ketiga, dan
4. menjadi **single point of failure** bagi keamanan komputer owner.

Profil risiko ini mengubah cara memilih bahasa: kriteria dominan bukan "cepat nulis", melainkan **memory safety tanpa runtime berat, determinisme latensi, permukaan serangan kecil, dan rantai pasok (supply chain) yang bisa diaudit**.

Dari 9 kandidat yang dievaluasi, dua finalis layak: **Rust** dan **Go**. Keduanya jauh di atas kandidat lain. Hasil pembobotan:

| Kriteria (bobot) | Rust | Go |
|---|---|---|
| Keamanan memori & attack surface (25%) | **10** | 7 |
| Performa & determinisme latensi (15%) | **10** | 8 |
| Ekosistem untuk kebutuhan FARcontrol (15%) | **9** | 9 |
| Deployability: binary tunggal, tanpa runtime (10%) | **10** | **10** |
| Maintainability jangka panjang (10%) | 8 | **9** |
| Kecepatan pengembangan v0.1 (10%) | 7 | **9** |
| Kematangan toolchain & supply chain (10%) | **9** | 9 |
| Ergonomi tools AI agent (CLI/HTTP/JSON) (5%) | 9 | 9 |
| **Skor tertimbang (100%)** | **9.15** | **8.30** |

**Verdict: Rust.** Keunggulan mutlak pada dua kriteria berbobot tertinggi (keamanan memori, determinisme latensi) tidak terkompensasi oleh keunggulan Go pada kecepatan pengembangan — apalagi scope v0.1.0 relatif kecil (~2.000–3.000 baris), sehingga biaya "Rust lebih lambat ditulis" terbatas dan dibayar sekali, sedangkan manfaat keamanannya dimiliki selama umur produk.

---

## 2. Metodologi

Kriteria diturunkan langsung dari karakteristik produk, bukan selera:

| # | Kriteria | Bobot | Alasan bobot |
|---|---|---|---|
| K1 | Keamanan memori & attack surface | 25% | Daemon mem-parsing input jaringan tidak-terpercaya; satu bug memori = RCE di mesin owner |
| K2 | Performa & determinisme latensi | 15% | Owner mensyaratkan control plane "wajib sangat cepat"; approval path harus responsif |
| K3 | Ekosistem (HTTP, SQLite, crypto, CLI) | 15% | Semua komponen FARcontrol butuh pustaka matang di 4 domain ini |
| K4 | Deployability | 10% | Self-hosted: ideal = satu static binary, tanpa runtime, tanpa dependency sistem |
| K5 | Maintainability jangka panjang | 10% | Proyek hidup bertahun-tahun; tipe ketat = refactor aman |
| K6 | Kecepatan pengembangan v0.1 | 10% | Waktu ke walking skeleton — penting tapi sekali bayar |
| K7 | Kematangan toolchain & supply chain | 10% | Dependency yang di-compile ke binary harus sedikit & terpercaya |
| K8 | Ergonomi AI agent | 5% | Antarmuka AI-first via HTTP/JSON/CLI — hampir netral bahasa |

Setiap kandidat dinilai per kriteria dengan justifikasi tertulis; skor akhir = Σ(bobot × skor)/10.

---

## 3. Eliminasi Awal (7 Kandidat Gugur)

### 3.1 C — gugur
Memory safety manual pada parser jaringan = kelas bug (buffer overflow, UAF, double-free) persis di permukaan serangan FARcontrol. Mayoritas eksploit memori berasal dari unsafe C/C++ (temuan berulang Microsoft & CISA sejak 2019). Tidak ada alasan memilih C untuk kode baru bertipe ini di 2026. **Skor efektif: 4/10.**

### 3.2 C++ — gugur
Sama tidak-aman dengan C (plus kompleksitas), dengan toolchain besar dan build system (CMake) yang menyulitkan distribusi binary tunggal. `std::` aman sebagian, tapi ekosistem HTTP/async tetap butuh pustaka pihak ketiga besar (Boost.Asio/Qt). **Skor efektif: 5/10.**

### 3.3 Zig — gugur (belum matang)
Menjanjikan (comptime, binary kecil), tapi belum mencapai 1.0: API breaking rutin, ekosistem HTTP/SQLite/kripto masih tipis, dan komunitas kecil = risiko maintainability. Menarik untuk dipantau, salah pilih untuk fondasi keamanan hari ini. **Skor efektif: 6/10.**

### 3.4 Python — gugur
Kecepatan prototipe kelas tertinggi, tapi: (a) butuh interpreter + venv di mesin owner = deployment lebih rapuh; (b) GIL + latensi GC + pustaka async yang kurang deterministik; (c) kualitas ketergantungan sangat bervariasi (supply chain PyPI berisiko tinggi — insiden typosquatting rutin); (d) tipe opsional — invariant keamanan lebih mudah bocor saat refactor. Untuk control plane yang hidup 24/7 ini pilihan lemah. **Skor efektif: 5.5/10.**

### 3.5 Node.js/TypeScript — gugur
Ergonomi JSON/HTTP bagus, tapi runtime V8 + npm = dua permukaan supply chain terbesar di industri; single-binary deployment cuma lewat bundler pihak ketiga; GC pause untuk server lokal masih ada. Tipe TS baik, tapi runtime-nya yang jadi masalah. **Skor efektif: 6.5/10.**

### 3.6 Java/Kotlin (JVM) — gugur
Sangat matang, tapi JVM di mesin owner = runtime ratusan MB, startup lambat, systemd integration kikuk, dan distribusi bukan "satu file". Latency JVM bagus setelah warm-up — kontrol lokal jalan terus, tapi deployment-nya kalah. **Skor efektif: 6.5/10.**

### 3.7 Crystal / D / Nim — gugur
Semua punya kompiler native + performa tinggi, tapi ketiganya punya ekosistem kecil: pustaka HTTP async + SQLite + CLI + crypto yang battle-tested tipis atau terpisah-pisah. Risiko "menulis sendiri crypto/HTTP edge" = justru sumber kerentanan. **Skor efektif: 6/10 masing-masing.**

---

## 4. Finalis: Rust vs Go — Head-to-Head

### 4.1 Keamanan Memori & Attack Surface (bobot 25%) — Rust 10, Go 7

- **Rust:** memory safety dijamin compiler untuk kode safe (borrow checker + aliasing rules). Kelas kerentanan yang membunuh daemon C/C++ (overflow, UAF, race di data) secara struktural tidak muncul di jalur safe. Unsafe dibatasi di pustaka kripto teraudit (ring/rustls), bukan kode aplikasi. Pemeriksaan tipe ketat juga menangkap kelas bug logika (misal scope/enum mismatch) saat compile.
- **Go:** memory-safe via GC + runtime bounds-check — jauh lebih baik dari C, dan secara praktis tidak kalah dari Rust untuk *bug memori murni*. Namun: (a) `nil` pointer dereference masih runtime panic (bukan compile error) — kelas "nil map / nil pointer" adalah bug runtime yang nyata di API layer; (b) `data race` hanya terdeteksi oleh race detector saat testing, bukan dijamin compiler — FARcontrol punya shared state (session table) yang diakses concurrent; (c) panic di goroutine tanpa recover = crash daemon — fail-closed tapi mengurangi availability.

Selisihnya bukan "Go tidak aman", melainkan: **Rust memindahkan kelas bug runtime Go ke compile-time.** Untuk komponen yang mengeksekusi perintah atas nama user, itu perbedaan kualitatif, bukan kuantitatif.

### 4.2 Performa & Determinisme Latensi (bobot 15%) — Rust 10, Go 8

- **Rust (tokio/axum):** tanpa GC. Alokasi prediktif, tidak ada stop-the-world. Latensi p99 stabil di mikro-detik untuk handler ringan; SQLite akses via FFI langsung. Binary release dengan LTO + strip menghasilkan footprint RAM ~5–15 MB untuk daemon seperti ini.
- **Go (net/http):** throughput dan latensi rata-rata sangat bagus — kompetitif. Tapi GC generational tetap menghasilkan jitter p99 (biasanya sub-milidetik di Go modern — jauh lebih baik dari reputasi lama). Untuk beban 1–10 req/detik milik FARcontrol, keduanya akan terasa identik secara absolut.

Nilai 10 vs 8 di sini lebih mencerminkan *determinisme* (tidak ada pause sama sekali) dan efisiensi memori (owner mungkin menjalankan ini di VPS kecil 512 MB bersama service lain) daripada throughput mentah.

### 4.3 Ekosistem untuk Kebutuhan FARcontrol (bobot 15%) — Rust 9, Go 9

| Kebutuhan | Rust | Go |
|---|---|---|
| HTTP server async | axum + tokio (de-facto standard, matang) | net/http stdlib (gold standard) |
| HTTP client | ureq/reqwest | net/http |
| SQLite | rusqlite (bundled amalgamation, tanpa dependency C sistem) | mattn/go-sqlite3 (butuh cgo) atau modernc.org/sqlite (pure Go, sedikit lebih lambat) |
| HMAC/SHA-256 | hmac + sha2 (RustCrypto, diaudit) | crypto/hmac, crypto/sha256 (stdlib) |
| Random aman | rand + getrandom (OS CSPRNG) | crypto/rand (stdlib) |
| CLI | clap (derive, best-in-class) | cobra (bagus) |
| Serialisasi | serde + serde_json (best-in-class) | encoding/json (bagus) |
| TLS (fase lanjut) | rustls (memori-aman, teraudit) | crypto/tls (stdlib) |

**Seri.** Keunggulan halus Go: crypto & HTTP ada di stdlib (dependency = 0). Keunggulan halus Rust: rusqlite bundled tidak butuh cgo — Go dengan mattn/go-sqlite3 **wajib cgo**, yang merusak cerita cross-compile binary-statis Go (jalan keluarnya modernc.org/sqlite, tapi itu pure-Go translation layer dengan performa sedikit turun dan binary membesar).

### 4.4 Deployability (bobot 10%) — Rust 10, Go 10

Keduanya menghasilkan binary native tunggal. Go (tanpa cgo) = static binary out-of-the-box — legendaris. Rust = binary dinamis glibc yang bisa distatic-kan dengan musl (`x86_64-unknown-linux-musl`). Untuk target Linux x86_64 milik owner sendiri, keduanya sempurna. **Seri.** (Catatan jujur: cross-compile Go lebih mulus; tapi v0.1.0 cuma target Linux.)

### 4.5 Maintainability Jangka Panjang (bobot 10%) — Rust 8, Go 9

- **Go:** kode paling mudah dibaca orang baru; satu cara idiomatis untuk segala hal; tooling (gofmt, go vet, race detector) menyatu. Onboarding engineer baru tercepat.
- **Rust:** sistem tipe ekspresif → refactor besar lebih aman (compiler menangkap semua titik perubahan), tapi borrow checker + lifetime = kurva belajar nyata; onboarding lebih lambat.

Go menang tipis di sini. Mitigasi Rust: scope kode v0.1.0 kecil dan terstruktur (modul state/auth/policy dipisah), kode idiomatik sederhana tanpa trik pintar.

### 4.6 Kecepatan Pengembangan v0.1 (bobot 10%) — Rust 7, Go 9

Go: dari nol ke walking skeleton ±30% lebih cepat untuk developer yang menguasai keduanya; compile ±10–30 detik vs Rust ±1–3 menit (release, LTO). Diterima apa adanya: **Go lebih cepat mengirim.** Kompensatorinya: scope v0.1.0 dijaga kecil (aturan owner #1: jangan over-engineer), dan hasil akhir Rust lebih tahan refactor.

### 4.7 Kematangan Toolchain & Supply Chain (bobot 10%) — Rust 9, Go 9

- **Rust:** crates.io + cargo audit/rustsec; dependency RustCrypto/rustls teraudit; dependensi FARcontrol dijaga minimum (±11 crate langsung, semua populer).
- **Go:** stdlib menutup kebutuhan inti → dependency eksternal nyaris nol — ini argumen supply-chain terkuat untuk Go.

Hampir seri; keunggulan Go (stdlib) vs keunggulan Rust (auditability binary + provenance). Keduanya memungkinkan rantai pasok pendek dan dapat diaudit — jauh di atas Python/Node (registri berisiko tinggi) dan C/C++ (fragmentasi).

### 4.8 Ergonomi AI Agent (bobot 5%) — Rust 9, Go 9

Antarmuka AI-first FARcontrol adalah **HTTP+JSON dan CLI**, bukan library — jadi hampir netral bahasa. Nilai sama. Sedikit plus untuk keduanya: binary tunggal memudahkan AI agent meng-install CLI `frtrol agent` di sandbox-nya (download satu file, `chmod +x`, selesai).

---

## 5. Analisis Risiko Khusus Keamanan (mengapa K1 diberi bobot 25%)

FARcontrol daemon melakukan, secara berurutan, untuk setiap request:

```
[parse bytes jaringan] → [verifikasi HMAC] → [cek session di SQLite] → [cek policy] → [spawn proses anak]
```

Tahap 1 dan 2 mem-parsing **byte dari pihak yang belum terpercaya**. Sejarah industri menunjukkan tahap ini persis tempat bug memori hidup: parsing = aritmetika pointer di C; parsing = panic surface di Go; parsing = error compile atau `Result` terpaksa ditangani di Rust.

Klaim yang bisa dibuktikan untuk Rust: **kelas CVE "memory corruption di parser input jaringan" tidak memiliki representasi di jalur kode safe Rust.** Ini bukan klaim "Rust bebas bug" — logic bug, crypto misuse, dan desain protokol buruk tetap mungkin (dan FARcontrol tetap mengandalkan policy + approval manusia sebagai lapisan utama). Klaimnya sempit tapi tepat sasaran: bahasa menghapus satu kelas kerentanan paling sering dieksploitasi dari komponen yang justru menanganinya.

Untuk Go, kelas residu: panic runtime pada input tak terduga (recovered oleh middleware, tapi tetap sinyal desain), data race yang lolos testing, dan cgo bila pakai go-sqlite3 (cgo = jendela ke dunia C di tengah binary Go).

**Keputusan pembobotan K1=25% adalah keputusan risiko, bukan fanatisme bahasa.** Dengan bobot 15%, kedua bahasa seri dan Go menang di tie-break velocity. Pemilik risiko (owner) secara eksplisit memprioritaskan kualitas komponen keamanan ("wajib yang bener-bener bagus"), sehingga 25% proporsional.

---

## 6. Trade-off yang Diterima (Kejujuran Penuh)

Dengan memilih Rust, FARcontrol menerima:

1. **Waktu pengembangan lebih lama** (±30–40% untuk tim yang baru belajar Rust). Mitigasi: scope v0.1.0 ketat, kode idiomatik sederhana, tanpa macro pintar.
2. **Compile time lebih lama** — mengganggu iterasi cepat. Mitigasi: `cargo check` untuk iterasi, release build hanya di akhir.
3. **Talent pool lebih kecil** bila proyek dibuka ke kontributor. Mitigasi: dokumentasi ADR lengkap + kode <3.000 baris.
4. **Kurva belajar** borrow checker untuk kontributor baru. Diterima.

Dengan memilih Rust, FARcontrol MENDAPAT (yang Go tidak berikan):

1. Jaminan compiler terhadap data race pada session table (akses concurrent dari banyak handler).
2. Ketiadaan GC → latensi p99 benar-benar datar, footprint RAM kecil dan konstan.
3. Ekspresivitas tipe (enum + Result + pattern matching) yang membuat **state machine session (pending → active → revoked/expired) tidak-bisa-salah-representasi**: transisi ilegal ditolak compiler.

Poin 3 adalah alasan teknis favorit: di Go, `status string` bisa berisi `"aktive"` — typo yang lolos review. Di Rust, `SessionStatus` adalah enum; nilai tidak-valid tidak kompilasi. Untuk mesin yang seluruh value proposition-nya adalah *state otorisasi yang benar*, ini bukan fitur bahasa — ini garansi produk.

---

## 7. Kondisi Revisit (Trigger Kaji-Ulang)

Keputusan ini direview ulang jika salah satu terjadi:

| Trigger | Aksi |
|---|---|
| Tim inti tidak mampu Rust dalam 2 sprint | Migrasi ke Go (interface HTTP/JSON identik, SQLite schema portable) |
| Kebutuhan pustaka sistem yang hanya layak via FFI kompleks | Evaluasi ulang komponen tersebut |
| v0.2+ butuh plugin scripting oleh user (bukan agent) | Tambahkan layer embedded scripting (mis. via WASM), bukan ganti bahasa |

Arsitektur FARcontrol sengaja dipisah: **protokol (HTTP/JSON) adalah kontrak, bahasa adalah implementasi.** Client agent (AI) tidak peduli daemon ditulis pakai apa. Migrasi bahasa tetap mahal, tapi tidak mengubah kontrak eksternal.

---

## 8. Verdict Final

> **FARcontrol 0.1.0 diimplementasikan dalam Rust (stable, edition 2021).**
>
> Rust menang karena dua alasan yang tepat sasaran untuk produk ini: (1) keamanan memori yang dijamin compiler pada komponen yang mem-parsing input jaringan tidak-terpercaya dan mengeksekusi perintah sistem — kriteria berbobot tertinggi sesuai profil risiko; (2) determinisme latensi tanpa GC untuk control plane yang owner minta "wajib sangat cepat" dengan footprint minimal.
>
> Go adalah pilihan sangat baik dan tetap menjadi fallback terdokumentasi (trigger revisit §7). Keduanya mengalahkan 7 kandidat lain dengan margin jelas.
>
> Skor akhir: **Rust 9.15 / Go 8.30** (skala 10, pembobotan §2).

---

## Appendix A — Dependency Plan (Rust, supply chain pendek)

| Crate | Peran | Kenapa dipercaya |
|---|---|---|
| tokio | async runtime | De-facto standard, disponsori AWS/Google/Microsoft |
| axum | HTTP framework | Tower ecosystem, tim Tokio |
| rusqlite (bundled) | SQLite | Binding resmi, amalgamation upstream SQLite |
| serde / serde_json | serialisasi | Paling banyak di-download di crates.io |
| clap | CLI | Standard de-facto |
| sha2 / hmac | kripto | RustCrypto, teraudit publik |
| rand / bs58 / hex / base64 | util | Kecil, teruji |
| ureq | HTTP client (CLI) | Kecil, rustls-based |
| toml / anyhow / chrono | util | Standard |

±11 crate langsung; tidak ada dependency framework besar selain axum; **tidak ada `unsafe` di kode aplikasi.**

## Appendix B — Catatan Metodologis

- Skor K1 Go=7 (bukan 5) karena Go tetap memory-safe di jalur normal — jarak ke Rust ada di kelas bug runtime (nil, race, panic), bukan memory corruption.
- Skor K2 Go=8 karena jitter GC modern sub-ms — nyaris tak terukur pada beban FARcontrol; keunggulan Rust ada di determinisme & RAM footprint, bukan throughput.
- Bobot ditetapkan SEBELUM penilaian kandidat (pre-registered) untuk mencegah bias konfirmasi terhadap bahasa favorit.
- Penulis menyadari penuh bahwa kekalahan velocity adalah biaya nyata yang akan dirasakan langsung selama development v0.1.0.
