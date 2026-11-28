#!/usr/bin/env python3
"""
DB API — satu interface, tiga backend (dipilih lewat env var).

Pipeline (pipeline_v2.py) dan verify_llm.py cuma manggil fungsi di
file ini, TIDAK pernah menyentuh DB langsung. Jadi ganti backend
tidak mengubah pipeline sama sekali. Tanda tangan fungsi tetap:

    DB(path)                    -> buka / buat store
    .save_candidate(rec)        -> True kalau URL baru, False kalau udah ada
    .update(url, **fields)      -> ubah status/score/evidence/yara_rules/method
    .exists(url)                -> True kalau URL udah ada
    .close()                    -> simpan & tutup
    .describe()                 -> string backend yang sedang dipakai

Backend (urutan prioritas, dicek saat DB() dibuat):
  1. Turso (dipakai kalau TURSO_DATABASE_URL di-set):
     export TURSO_DATABASE_URL="libsql://imphnen-xxx.turso.io"
     export TURSO_AUTH_TOKEN="eyJ..."
     Butuh: pip install libsql-experimental
     Skema: schema.sql (dijalankan otomatis saat pertama connect)
  2. Postgres/Neon (dipakai kalau DATABASE_URL diawali postgres://):
     export DATABASE_URL="postgres://user:pass@host/db?sslmode=require"
     Butuh: pip install psycopg[binary]
  3. JSONL lokal (default, tanpa setup apa pun):
     file candidates.jsonl / pipeline.jsonl di folder kerja.
     Ini yang dipakai sampai sekarang (28 Nov 2026).

Record (dict) yang disimpan pipeline:
    url, canonical, kind ('biasa'|'injected'),
    status ('candidate'|'verified'|'discarded'|'queued'|'submitted'),
    score, title, snippet, evidence, source, created_at,
    yara_rules, method, llm_verdict, llm_reason

Disiapkan 28 Nov 2026 — DB beneran baru dibuat setelah techmeet
Jumat 4 Des 2026 (saat itu baru dikasih akses DeepSeek Netra).
Sampai saat itu, pipeline tetap jalan dengan backend JSONL.
"""
import json
import os

DEFAULT_PATH = "candidates.jsonl"
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")

FIELDS = [
    "url", "canonical", "kind", "status", "score", "title", "snippet",
    "evidence", "source", "yara_rules", "method", "llm_verdict",
    "llm_reason", "created_at",
]


def _load_schema():
    if os.path.exists(SCHEMA_PATH):
        with open(SCHEMA_PATH, encoding="utf-8") as f:
            return f.read()
    return ""


class _SQLBackend:
    """Backend SQL generik (Turso/libSQL dan Postgres) — beda di placeholder."""

    def __init__(self, conn, placeholder):
        self.conn = conn
        self.ph = placeholder  # '?' untuk libsql, '%s' untuk psycopg
        schema = _load_schema()
        if schema:
            cur = self.conn.cursor()
            # schema.sql berisi beberapa statement; jalankan satu-satu
            for stmt in schema.split(";"):
                stmt = stmt.strip()
                if stmt:
                    cur.execute(stmt)
            self.conn.commit()

    def _norm(self, rec):
        return {k: rec.get(k, "" if k != "score" else 0) for k in FIELDS}

    def save_candidate(self, rec):
        r = self._norm(rec)
        cols = ", ".join(FIELDS)
        phs = ", ".join([self.ph] * len(FIELDS))
        cur = self.conn.cursor()
        try:
            cur.execute(
                f"INSERT INTO candidates ({cols}) VALUES ({phs})",
                [r[k] for k in FIELDS],
            )
            self.conn.commit()
            return True
        except Exception:
            self.conn.rollback()
            return False  # duplikat (PRIMARY KEY url) atau error lain

    def update(self, url, **fields):
        fields = {k: v for k, v in fields.items() if k in FIELDS and k != "url"}
        if not fields:
            return False
        sets = ", ".join(f"{k} = {self.ph}" for k in fields)
        cur = self.conn.cursor()
        try:
            cur.execute(
                f"UPDATE candidates SET {sets}, updated_at = datetime('now') "
                f"WHERE url = {self.ph}",
                list(fields.values()) + [url],
            )
            self.conn.commit()
            return cur.rowcount > 0
        except Exception:
            self.conn.rollback()
            return False

    def exists(self, url):
        cur = self.conn.cursor()
        cur.execute(f"SELECT 1 FROM candidates WHERE url = {self.ph} LIMIT 1", [url])
        return cur.fetchone() is not None

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


class _JSONLBackend:
    def __init__(self, path):
        self.path = path
        self._rows = {}
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        self._rows[rec["url"]] = rec
                    except (json.JSONDecodeError, KeyError):
                        continue

    def _flush(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for rec in self._rows.values():
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        os.replace(tmp, self.path)

    def save_candidate(self, rec):
        if rec["url"] in self._rows:
            return False
        self._rows[rec["url"]] = dict(rec)
        self._flush()
        return True

    def update(self, url, **fields):
        if url not in self._rows:
            return False
        self._rows[url].update(fields)
        self._flush()
        return True

    def exists(self, url):
        return url in self._rows

    def close(self):
        self._flush()


class DB:
    def __init__(self, path=None):
        self.backend_name = "jsonl"
        self._backend = None

        turso_url = os.environ.get("TURSO_DATABASE_URL", "")
        pg_url = os.environ.get("DATABASE_URL", "")

        if turso_url:
            try:
                import libsql  # pip install libsql-experimental
                conn = libsql.connect(
                    turso_url, auth_token=os.environ.get("TURSO_AUTH_TOKEN", "")
                )
                self._backend = _SQLBackend(conn, "?")
                self.backend_name = f"turso ({turso_url})"
                return
            except Exception as e:
                print(f"WARNING: Turso gagal connect ({e}) — fallback ke JSONL lokal.")
        elif pg_url.startswith("postgres://") or pg_url.startswith("postgresql://"):
            try:
                import psycopg  # pip install psycopg[binary]
                conn = psycopg.connect(pg_url)
                self._backend = _SQLBackend(conn, "%s")
                self.backend_name = "postgres/neon"
                return
            except Exception as e:
                print(f"WARNING: Postgres gagal connect ({e}) — fallback ke JSONL lokal.")

        # Fallback: JSONL lokal (default sampai DB beneran dibuat)
        p = path or os.environ.get("PIPELINE_DB", DEFAULT_PATH)
        if p.endswith(".db"):
            p = p[:-3] + ".jsonl"
        self.path = p
        self._backend = _JSONLBackend(p)
        self.backend_name = f"jsonl ({p})"

    def describe(self):
        return self.backend_name

    def save_candidate(self, rec):
        return self._backend.save_candidate(rec)

    def update(self, url, **fields):
        return self._backend.update(url, **fields)

    def exists(self, url):
        return self._backend.exists(url)

    def close(self):
        self._backend.close()

