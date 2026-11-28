#!/usr/bin/env python3
"""migrate_jsonl_to_db.py — Pindahkan pipeline.jsonl (placeholder) ke DB bersama.

Dipakai SEKALI saat DB Turso/Neon sudah dibuat (setelah techmeet Jumat 4 Des 2026).
Setelah migrasi, pipeline_v2.py + verify_llm.py otomatis pakai DB itu
(lewat db.py yang sama) — tidak perlu ubah pipeline.

Cara pakai:
    # 1. Isi env dari DB_SETUP.md (Turso):
    export TURSO_DATABASE_URL="libsql://imphnen-xxx.turso.io"
    export TURSO_AUTH_TOKEN="eyJ..."
    # 2. Jalankan (default: pipeline.jsonl di folder ini):
    python3 migrate_jsonl_to_db.py
    python3 migrate_jsonl_to_db.py --db pipeline-11e41f48.jsonl --limit 10   # tes 10 dulu

Aman diulang: URL yang sudah ada di DB di-skip (dihitung sebagai 'sudah ada').
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db import DB  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="pipeline.jsonl", help="file JSONL sumber")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"ERROR: file tidak ada: {args.db}", file=sys.stderr)
        return 1

    db = DB()
    print(f"Target DB: {db.describe()}")
    rows = [json.loads(l) for l in open(args.db, encoding="utf-8") if l.strip()]
    if args.limit:
        rows = rows[: args.limit]
    new = dup = 0
    for r in rows:
        # db.py menerima field yang sama seperti JSONL
        if db.save_candidate(r):
            new += 1
        else:
            dup += 1
    db.close()
    print(f"Selesai: {len(rows)} baris dibaca, baru {new}, sudah ada {dup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
