#!/usr/bin/env python3
"""verify_llm.py — Tahap LLM di pipeline hybrid IMPHNEN.

Alur hybrid: SearXNG -> whitelist -> YARA -> LLM (hanya yang RAGU) -> submit.
Script ini HANYA memverifikasi link yang ragu, bukan semua URL.

Ragu = status verified DAN (method == 'keyword' ATAU domain berita
ATAU judul/snippet kayak artikel). Aturan ini sama dengan yang dipakai
untuk membangun queue_ragu.txt (28 Nov 2026, 180 link dari 1.064 baris).

Cara pakai (di WSL, folder ~/searxng-docker/searxng-official):
    export DEEPSEEK_API_KEY="sk-..."
    ~/yara-env/bin/python verify_llm.py                 # semua yang ragu
    ~/yara-env/bin/python verify_llm.py --limit 20      # tes 20 dulu
    ~/yara-env/bin/python verify_llm.py --list-only     # lihat daftar ragu, tanpa panggil LLM
    ~/yara-env/bin/python verify_llm.py --dry-run       # sama, tanpa panggil LLM

Env (opsional, default = DeepSeek gratis peserta hackathon):
    DEEPSEEK_API_KEY   (wajib kalau mau panggil LLM)
    LLM_API_URL        (default https://api.deepseek.com/v1/chat/completions)
    LLM_MODEL          (default deepseek-chat)
    LLM_BATCH          (default 20 link per request)

Hasil:
- pipeline.jsonl di-update in-place: link JUDOL tetap verified
  (method jadi 'llm', llm_verdict='JUDOL'), link BUKAN/ARTIKEL jadi
  discarded (method='llm'). File ditulis ulang per batch, jadi
  Ctrl+C tidak menghilangkan hasil batch yang sudah selesai.
- llm_results.jsonl: 1 baris per link yang sudah di-LLM, berisi
  verdict + alasan (audit trail).
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from urllib.parse import urlparse

DB_PATH = "pipeline.jsonl"
RESULTS_PATH = "llm_results.jsonl"

NEWS_SUFFIXES = (
    "detik.com", "liputan6.com", "kompas.com", "kompasiana.com",
    "bbc.com", "bola.com", "cnn.com", "tempo.co", "tribunnews.com",
    "suara.com", "viva.co.id",
)
ARTICLE_PHRASES = (
    "apa itu", "pengertian", "arti ", "artikel", "cara mengatasi",
    "dampaknya", "jenis dan", "contoh kalimat",
)

PROMPT = """Kamu adalah verifier situs judi online untuk hackathon anti-judol.
Klasifikasikan setiap link di bawah ini berdasarkan URL, judul, dan snippet-nya.

Kategori:
- JUDOL: situs judi online AKTIF (slot/togel/casino/poker, ada login/daftar/deposit/main).
  Contoh: rtp-hantugame.com, sloto69.id, togelcc.app, livepools.id.
- ARTIKEL: halaman berita/artikel/kamus yang MEMBAHAS judi, BUKAN situs judi.
  Contoh: liputan6.com "apa itu deposit", detik.com/tag/judi-online, wikipedia.org/wiki/Bandar.
- BUKAN: situs lain yang bukan judi dan bukan artikel soal judi
  (halaman bantuan, login Google/Microsoft, kamus, toko, dll).

Jawab HANYA dalam JSON array, satu objek per link, urutan sama seperti input:
[{"n": 1, "verdict": "JUDOL", "reason": "alasan singkat max 10 kata"}, ...]
Jangan tambah teks di luar JSON.

Link:
{items}
"""


def is_news(url: str) -> bool:
    host = urlparse(url.lower()).netloc
    host = host[4:] if host.startswith("www.") else host
    return any(host == s or host.endswith("." + s) for s in NEWS_SUFFIXES)


def is_doubtful(rec: dict) -> str:
    """Kembalikan alasan ragu, atau '' kalau tidak ragu."""
    if rec.get("status") != "verified":
        return ""
    reasons = []
    if rec.get("method") == "keyword":
        reasons.append("keyword-only (tanpa YARA)")
    if is_news(rec.get("url", "")):
        reasons.append("domain berita")
    text = " ".join([
        rec.get("title", ""), rec.get("snippet", ""), rec.get("evidence", ""),
    ]).lower()
    if any(p in text for p in ARTICLE_PHRASES):
        if "domain berita" not in reasons:
            reasons.append("judul/snippet kayak artikel")
    return "; ".join(reasons)


def load_db(path):
    rows = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            rows = [json.loads(l) for l in f if l.strip()]
    return rows


def save_db(path, rows):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


def call_llm(items, api_url, api_key, model):
    """items: list of dict {n, url, title, snippet}. Return list of verdicts."""
    lines = []
    for it in items:
        lines.append(
            f"{it['n']}. {it['url']} | judul: {it.get('title','')[:120]} "
            f"| snippet: {it.get('snippet','')[:200]}"
        )
    payload = {
        "model": model,
        # JANGAN pakai PROMPT.format() — prompt berisi kurung kurawal JSON
        # literal ({"n": 1, ...}) yang .format() kira placeholder -> KeyError '"n"'.
        # Bug ini ketemu 28 Nov 2026 di run Gemini pertama (batch 1 GAGAL '"n"').
        "messages": [{"role": "user", "content": PROMPT.replace("{items}", "\n".join(lines))}],
        "temperature": 0,
    }
    # Netra DeepSeek V4.1 Flash: matikan reasoning, kalau tidak output
    # JSON-nya bisa tercampur reasoning trace (docs Netra, 28 Nov 2026).
    if "netraruntime" in api_url or "deepseek-v4.1" in model:
        payload["reasoning"] = {"enabled": False}
    body = json.dumps(payload).encode()
    # Gemini juga menerima key lewat header x-goog-api-key; kirim keduanya
    # (Bearer + x-goog-api-key) biar tidak ditolak "Please pass a valid API key".
    req = urllib.request.Request(
        api_url, data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}",
                 "x-goog-api-key": api_key},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        # Gemini/DeepSeek mengembalikan pesan error di body — tampilkan,
        # jangan cuma "HTTP Error 400" yang tidak menjelaskan apa-apa.
        body = e.read().decode(errors="replace")[:500]
        raise RuntimeError(f"HTTP {e.code}: {body}") from e
    content = data["choices"][0]["message"]["content"].strip()
    # Simpan raw response buat debug kalau JSON-nya gagal di-parse
    with open("llm_raw_last.txt", "w", encoding="utf-8") as f:
        f.write(content)
    # LLM kadang membungkus JSON dengan ```json ... ```
    if content.startswith("```"):
        content = content.strip("`").strip()
        if content.startswith("json"):
            content = content[4:].strip()
    return json.loads(content)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--limit", type=int, default=0, help="batasi jumlah link (0 = semua)")
    ap.add_argument("--batch", type=int, default=int(os.environ.get("LLM_BATCH", "20")))
    ap.add_argument("--list-only", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    rows = load_db(args.db)
    by_url = {r["url"]: r for r in rows}
    doubtful = []
    for r in rows:
        why = is_doubtful(r)
        if why:
            doubtful.append((r, why))
    print(f"DB: {args.db} — total {len(rows)} baris")
    print(f"Ragu: {len(doubtful)} link "
          f"(keyword-only + domain berita + judul artikel)")

    if args.list_only or args.dry_run:
        for r, why in doubtful[: args.limit or None]:
            print(f"  - {r['url']}  [{why}]")
        print("(--list-only/--dry-run: LLM tidak dipanggil)")
        return 0

    # Key dibaca dari salah satu var ini.
    # PENTING: kalau URL-nya Gemini, GOOGLE_API_KEY harus menang atas
    # DEEPSEEK_API_KEY/LLM_API_KEY yang mungkin masih ke-set di shell dari
    # percobaan sebelumnya — key DeepSeek yang nyasar ke Gemini akan
    # ditolak Google dengan "Please pass a valid API key" (28 Nov 2026).
    # Kalau URL-nya Netra, NETRA_API_KEY menang (docs netraruntime.com, 28 Nov 2026).
    api_url = os.environ.get("LLM_API_URL", "https://api.deepseek.com/v1/chat/completions")
    is_gemini = "generativelanguage.googleapis.com" in api_url
    is_netra = "netraruntime" in api_url
    if is_gemini:
        api_key = (
            os.environ.get("GOOGLE_API_KEY", "")
            or os.environ.get("LLM_API_KEY", "")
            or os.environ.get("DEEPSEEK_API_KEY", "")
        )
    elif is_netra:
        api_key = (
            os.environ.get("NETRA_API_KEY", "")
            or os.environ.get("LLM_API_KEY", "")
            or os.environ.get("DEEPSEEK_API_KEY", "")
        )
    else:
        api_key = (
            os.environ.get("LLM_API_KEY", "")
            or os.environ.get("DEEPSEEK_API_KEY", "")
            or os.environ.get("GOOGLE_API_KEY", "")
            or os.environ.get("NETRA_API_KEY", "")
        )
    if not api_key:
        print("ERROR: API key belum di-set.", file=sys.stderr)
        print("  Gemini:  export GOOGLE_API_KEY=\"AIza...\"  (dari aistudio.google.com)", file=sys.stderr)
        print("  DeepSeek: export DEEPSEEK_API_KEY=\"sk-...\"", file=sys.stderr)
        print("  Lalu jalankan lagi. Atau pakai --list-only untuk lihat daftar ragu.", file=sys.stderr)
        return 1
    api_url = os.environ.get("LLM_API_URL", "https://api.deepseek.com/v1/chat/completions")
    model = os.environ.get("LLM_MODEL", "deepseek-chat")

    targets = doubtful[: args.limit or None]
    print(f"LLM: {model} @ {api_url} — batch {args.batch}, target {len(targets)} link")
    kept = discarded = failed = 0
    try:
        for start in range(0, len(targets), args.batch):
            chunk = targets[start:start + args.batch]
            items = [{
                "n": i + 1,
                "url": r["url"],
                "title": r.get("title", ""),
                "snippet": r.get("snippet", "") or r.get("evidence", "")[:200],
            } for i, (r, _) in enumerate(chunk)]
            # Retry kalau model overload (503/429) — Gemini 3.8-flash
            # kena ini 28 Nov 2026 ("high demand, try again later").
            # Jangan langsung buang batch-nya; coba lagi 3x dengan jeda
            # makin lama (30s, 60s, 120s) sebelum menyerah.
            verdicts = None
            last_err = None
            for attempt in range(1, 4):
                try:
                    verdicts = call_llm(items, api_url, api_key, model)
                    break
                except Exception as e:
                    last_err = e
                    if ("503" in str(e) or "429" in str(e)) and attempt < 3:
                        wait = 30 * attempt
                        print(f"  batch {start//args.batch + 1}: overload ({e}) — retry {attempt}/3 setelah {wait}s")
                        time.sleep(wait)
                    else:
                        break
            if verdicts is None:
                print(f"  batch {start//args.batch + 1}: GAGAL ({last_err}) — lanjut batch berikutnya")
                failed += len(chunk)
                time.sleep(5)
                continue
            with open(RESULTS_PATH, "a", encoding="utf-8") as out:
                for it, v in zip(items, verdicts):
                    verdict = str(v.get("verdict", "")).upper().strip()
                    reason = str(v.get("reason", ""))[:120]
                    rec = by_url[it["url"]]
                    if verdict == "JUDOL":
                        rec["method"] = "llm"
                        rec["llm_verdict"] = "JUDOL"
                        rec["llm_reason"] = reason
                        kept += 1
                    elif verdict in ("ARTIKEL", "BUKAN"):
                        rec["status"] = "discarded"
                        rec["method"] = "llm"
                        rec["llm_verdict"] = verdict
                        rec["llm_reason"] = reason
                        discarded += 1
                    else:
                        failed += 1
                    out.write(json.dumps({
                        "url": it["url"], "verdict": verdict,
                        "reason": reason,
                    }, ensure_ascii=False) + "\n")
            save_db(args.db, rows)
            print(f"  batch {start//args.batch + 1}: {len(chunk)} link "
                  f"-> kept {kept} total, discarded {discarded} total")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nCtrl+C — hasil batch yang sudah selesai sudah tersimpan di DB.")
    print(f"\nSelesai: JUDOL (tetap verified) {kept}, "
          f"ARTIKEL/BUKAN (discarded) {discarded}, gagal {failed}")
    print(f"Audit trail: {RESULTS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

