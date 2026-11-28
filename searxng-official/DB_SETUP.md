# DB Bersama IMPHNEN — Setup (disiapkan 28 Nov 2026)

**Status: HOLD sampai techmeet Jumat 4 Des 2026.**
Sampai saat itu, pipeline tetap jalan dengan JSONL lokal
(`pipeline.jsonl`, 1.064 baris terakhir). DB beneran baru dibuat
setelah techmeet — saat itu juga baru dikasih akses DeepSeek Netra.

## Pilihan: Turso (utama)

Kenapa Turso: SQLite di cloud, migrasi paling gampang dari JSONL,
dan pipeline tidak perlu diubah (cuma ganti env var di `db.py`).

**Catatan batas:** Turso free diarsipkan setelah **10 hari tidak aktif**.
Timeline 4–10 Des cuma 6 hari, jadi aman — asal ada yang query
DB minimal sekali sebelum 14 Des.

## Langkah setup (setelah techmeet)

```bash
# 1. Install CLI Turso (di WSL) + login
curl -sSfL https://get.tur.so/install.sh | bash
turso auth login

# 2. Buat database
turso db create imphnen
turso db show imphnen --url
turso db tokens create imphnen

# 3. Install driver Python (di yara-env)
~/yara-env/bin/pip install libsql-experimental

# 4. Set env (di terminal WSL, tiap kali run — atau taruh di ~/.bashrc)
export TURSO_DATABASE_URL="libsql://imphnen-xxx.turso.io"
export TURSO_AUTH_TOKEN="eyJ..."

# 5. Migrasi data lama (1.064 baris dari pipeline.jsonl)
cd ~/searxng-docker/searxng-official
python3 migrate_jsonl_to_db.py --limit 10   # tes 10 dulu
python3 migrate_jsonl_to_db.py              # full — aman diulang, duplikat di-skip

# 6. Cek backend yang dipakai
python3 -c "from db import DB; print(DB().describe())"
# harus keluar: turso (libsql://...)
```

Setelah langkah 6, `pipeline_v2.py` dan `verify_llm.py` otomatis
pakai Turso — **tidak ada file pipeline yang perlu diubah**.

## Alternatif: Neon (Postgres)

Kalau Turso bermasalah, pakai Neon (tidak diarsipkan karena tidak aktif,
compute scale-to-zero setelah 5 menit idle, kuota 100 CU-hours/bulan):

```bash
~/yara-env/bin/pip install "psycopg[binary]"
export DATABASE_URL="postgres://user:pass@host/db?sslmode=require"
python3 migrate_jsonl_to_db.py
```

## Skema

`schema.sql` — tabel `candidates` (url PRIMARY KEY, status flow
candidate → verified → queued → submitted, kolom yara_rules, method,
llm_verdict, llm_reason) + index antrean submit. Dijalankan otomatis
oleh `db.py` saat pertama connect ke Turso/Neon.

## Yang dibagikan ke tim (Daffa + Gustav)

Mereka cukup set 2 env var yang sama (`TURSO_DATABASE_URL` +
`TURSO_AUTH_TOKEN`) di mesin masing-masing, lalu jalankan pipeline
dari repo yang sama. Satu DB, tiga orang, duplikat ditolak oleh
PRIMARY KEY `url`.
