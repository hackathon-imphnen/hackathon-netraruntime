#!/usr/bin/env python3
"""
IMPHNEN Hackathon - Tahap 1 (Jalur Teks) - pipeline gabungan v2 (YARA)
SearXNG -> dedupe -> classify (biasa / injected .go.id/.ac.id)
        -> fetch exact URL -> YARA (+ keyword-count fallback) -> SQLite

Bedanya dari v1 (pipeline.py): verifikasi bukan lagi hitung kata mentah
(score >= 3). Sekarang dicek pakai aturan YARA TangerangKota-CSIRT
(judol_keywords_.yar, 6 rule: Judol_1 slot, Judol_2 togel, Judol_3
casino, Judol_4 provider+game, Judol_5 deposit/promo, Judol_6 stuffing).
Satu URL dinyatakan verified kalau YARA match ATAU keyword-count >= 3
— OR, bukan AND. Alasannya (dites 28 Nov 2026 di VM):
  - slotgacorplay.com -> YARA Judol_4 match (provider+game+action)
  - gacor305.app/slots -> YARA Judol_4 match
  - kejari-poso.kejaksaan.go.id/.../slot-gacor/ -> YARA Judol_1 match
    (halaman inject MASIH HIDUP saat dites, bukan cuma cache Bing)
  - apinaga.io -> YARA TIDAK match (JS-rendered, frasa multi-kata
    nggak ada di HTML mentah) padahal keyword-count 33 -> tetap
    verified lewat fallback keyword. YARA saja akan membuang situs
    JS-heavy seperti ini.
  - YARA juga TIDAK membedakan artikel penjelasan ("Understanding
    Slot Gacor") dari situs judi beneran — keduanya bisa match
    Judol_1. Jadi YARA = bukti lebih kuat, bukan filter sempurna.
    Keputusan akhir tetap di re-check manual sebelum submit 5 Des.

Setup di WSL (sekali saja):
  python3 -m venv ~/yara-env && ~/yara-env/bin/pip install yara-python
  # lalu jalanin pakai venv itu (lihat bawah). Tanpa yara-python,
  # script tetap jalan, cuma verifikasi jadi keyword-count saja (v1).

Jalanin:  ~/yara-env/bin/python pipeline_v2.py
          (atau: python3 pipeline_v2.py — kalau yara-python tidak
           ketemu, otomatis fallback keyword-count)
Stop:     Ctrl+C kapan aja - progress yang udah kekumpul
          langsung disimpan ke pipeline.db, nggak hilang.
          File yang sama (pipeline.db) bisa dipakai v1 dan v2
          bergantian — kolom baru ditambah otomatis, data lama aman.

SearXNG harus jalan dulu di http://localhost:8080
(atau set env SEARXNG_URL, misal http://localhost:8080)
Keyword:  KEYWORDS_FILE=keywords_91.txt (default: file itu kalau ada
          di folder yang sama, kalau tidak ada pakai 12 keyword awal)
YARA:     YARA_RULES=judol_keywords_.yar (default: file itu kalau ada
          di folder yang sama)
"""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from urllib.parse import urlparse

# DB lewat API placeholder (db.py) — pipeline TIDAK menyentuh
# sqlite/Postgres langsung. Tanpa setup DB pun jalan: backend
# placeholder-nya file candidates.jsonl. Nanti pas DB beneran
# disetup, ganti isi db.py saja, pipeline ini tidak berubah.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db import DB  # noqa: E402

SEARXNG_URL = os.environ.get("SEARXNG_URL", "http://localhost:8080").rstrip("/")
DB_PATH = os.environ.get("PIPELINE_DB", "pipeline.db")
DELAY = 1.0  # detik antar query SearXNG

# 12 keyword awal (ganti / tambah sendiri; atau isi KEYWORDS_FILE)
KEYWORDS = [
    "slot gacor", "situs slot gacor", "togel online", "bandar togel",
    "slot maxwin", "situs togel terpercaya", "slot gacor hari ini",
    "judi slot online", "togel 4d", "slot deposit qris",
    "situs slot terpercaya", "agen togel online",
]
# kalau ada file keyword (1 per baris), pakai itu.
# Default: keywords_91.txt di folder yang sama (91 keyword unik,
# sumber: INFOKOM-KI/yara-scan-judol + cakipin/anti-judol).
# Baris kosong dan baris komentar (# ...) di-skip.
_HERE = os.path.dirname(os.path.abspath(__file__))
KEYWORDS_FILE = os.environ.get("KEYWORDS_FILE", "") or os.path.join(_HERE, "keywords_91.txt")
if KEYWORDS_FILE and os.path.exists(KEYWORDS_FILE):
    with open(KEYWORDS_FILE, encoding="utf-8") as f:
        KEYWORDS = [l.strip() for l in f
                    if l.strip() and not l.strip().startswith("#")]

JUDOL_WORDS = ["slot", "togel", "judi", "gacor", "maxwin", "rtp", "bandar"]
INJECTED_SUFFIXES = (".go.id", ".ac.id", ".sch.id", ".or.id")

# ---------- Whitelist: domain yang jelas BUKAN judol ----------
# Ditambah 28 Nov 2026 setelah audit pipeline.jsonl (789 baris):
# 246 verified keyword-only ternyata isinya situs bantuan/login/
# ensiklopedia (support.microsoft.com, support.google.com, Wikipedia,
# YouTube, Meta, dll) yang kebawa keyword umum ('login', 'daftar').
# Domain di sini langsung discarded TANPA fetch — hemat waktu dan
# tidak mencemari antrean. Cek suffix: 'google.com' juga menolak
# 'support.google.com', 'accounts.google.com', dst.
# HATI-HATI: jangan masukkan portal berita (detik.com, liputan6.com)
# ke sini — tag-page mereka soal judi online memang bukan situs judi,
# tapi itu urusan YARA/re-check manual, bukan whitelist.
WHITELIST_SUFFIXES = (
    "wikipedia.org", "wikimedia.org", "wikihow.com",
    "google.com", "youtube.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "windows.com", "office.com",
    "meta.com", "facebook.com", "instagram.com", "whatsapp.com",
    "apple.com", "amazon.com", "github.com", "stackoverflow.com",
    "reddit.com", "x.com", "twitter.com", "linkedin.com",
    "cambridge.org", "britannica.com", "kbbi.co.id", "kbbi.web.id",
    "chatgpt.com", "openai.com", "gemini.google",
)

def is_whitelisted(url: str) -> bool:
    host = urlparse(url.lower()).netloc
    host = host[4:] if host.startswith("www.") else host
    return any(host == s or host.endswith("." + s) for s in WHITELIST_SUFFIXES)

# ---------- YARA ----------
# Aturan TangerangKota-CSIRT v1.0 (2026-05-06), file judol_keywords_.yar.
# Kalau yara-python tidak ter-install, YARA_RULES=None dan verifikasi
# jatuh ke keyword-count saja (perilaku v1) — script tetap jalan.
try:
    import yara as _yara
except ImportError:
    _yara = None
YARA_PATH = os.environ.get("YARA_RULES", "") or os.path.join(_HERE, "judol_keywords_.yar")
YARA_RULES = None
YARA_ERR = ""
if _yara is not None and os.path.exists(YARA_PATH):
    try:
        YARA_RULES = _yara.compile(filepath=YARA_PATH)
    except Exception as e:  # file .yar rusak / versi tidak cocok
        YARA_ERR = str(e)
elif _yara is None:
    YARA_ERR = "yara-python tidak ter-install (pip install yara-python)"

# ---------- DB (placeholder, lihat db.py) ----------
# Dulu di sini ada init_db() sqlite langsung. Sekarang semua akses
# DB lewat DB() dari db.py — backend-nya candidates.jsonl sampai
# DB beneran disetup. DB_PATH di bawah cuma nama file store-nya.

def canonical(url: str) -> str:
    """Bentuk kanonik versi panitia: tanpa http/https, www., query, #, trailing slash."""
    u = urlparse(url.lower())
    host = u.netloc[4:] if u.netloc.startswith("www.") else u.netloc
    path = u.path.rstrip("/") or ""
    return host + path

def classify(url: str, title: str, snippet: str) -> str:
    host = urlparse(url.lower()).netloc
    if host.endswith(INJECTED_SUFFIXES):
        return "injected"
    return "biasa"

# ---------- SearXNG ----------
def searxng_search(query: str, engine: str, pageno: int):
    url = (f"{SEARXNG_URL}/search?q={urllib.parse.quote(query)}"
           f"&format=json&engines={engine}&pageno={pageno}")
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.load(r)

# ---------- fetch exact URL + verifikasi YARA ----------
def verify(url: str, kind: str = "biasa"):
    """Fetch path lengkapnya, lalu verifikasi dua lapis:
    1. YARA (kalau rules berhasil di-load): match frasa multi-kata /
       provider+game / deposit-promo dari TangerangKota-CSIRT.
    2. Keyword-count (fallback v1): jumlah kata judol di HTML mentah.
    Aturan lolos (v3, diubah 28 Nov 2026 setelah run 91 keyword):
    - kind='biasa': verified kalau YARA match ATAU keyword-count >= 3.
    - kind='injected' (.go.id/.ac.id): verified HANYA kalau YARA match.
      Keyword doang tidak cukup — soalnya kata 'slot' di kode JS
      (misal Moodle moodle-mod_quiz-util-slot di kuliah.uajy.ac.id,
      score 3, YARA kosong) lolos sebagai false positive di v2.
    Return dict: verified, method ('yara' / 'keyword' / 'yara+keyword'
    / '' kalau tidak lolos), yara_rules (list nama rule), yara_score
    (jumlah meta score rule yang match), score (keyword-count),
    evidence (cuplikan HTML sekitar kata judol).
    Raise kalau fetch gagal (mati / bersih / diblokir) — pemanggil
    akan menandai discarded, sama seperti v1."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        html = r.read()
    low = html.decode("utf-8", "ignore").lower()
    counts = {k: low.count(k) for k in JUDOL_WORDS if k in low}
    score = sum(counts.values())
    # bukti: 300 karakter pertama yang mengandung kata judol
    evidence = ""
    m = re.search(r".{0,120}(slot|togel|judi|gacor).{0,120}", low, re.S)
    if m:
        evidence = m.group(0).strip()
    # Lapis YARA — match di bytes mentah (filesize < 5MB di rule).
    yara_rules, yara_score = [], 0
    if YARA_RULES is not None:
        try:
            for match in YARA_RULES.match(data=html):
                yara_rules.append(match.rule)
                yara_score += int(match.meta.get("score", 0) or 0)
        except Exception:
            yara_rules, yara_score = [], 0  # HTML terlalu besar / aneh
    yara_ok = bool(yara_rules)
    kw_ok = score >= 3
    if kind == "injected":
        # Wajib YARA — keyword doang ketipu 'slot' di JS (Moodle dkk).
        if yara_ok and kw_ok:
            method = "yara+keyword"
        elif yara_ok:
            method = "yara"
        else:
            method = ""
    else:
        if yara_ok and kw_ok:
            method = "yara+keyword"
        elif yara_ok:
            method = "yara"
        elif kw_ok:
            method = "keyword"
        else:
            method = ""
    return {"verified": bool(method), "method": method,
            "yara_rules": yara_rules, "yara_score": yara_score,
            "score": score, "evidence": evidence}

# ---------- main ----------
def main():
    db = DB(DB_PATH)
    seen = set()
    stats = {"queries": 0, "raw": 0, "new": 0, "verified": 0,
             "discarded": 0, "injected": 0, "yara": 0}
    start = time.time()
    print(f"SearXNG: {SEARXNG_URL} | DB (placeholder): {db.path} | keyword: {len(KEYWORDS)}")
    if YARA_RULES is not None:
        print(f"YARA: aktif ({YARA_PATH}, 6 rule Judol_1..6)")
    else:
        print(f"YARA: NONAKTIF ({YARA_ERR}) — verifikasi jadi keyword-count saja")
    print("Stop kapan aja dengan Ctrl+C - progress langsung tersimpan.\n")

    try:
        for q in KEYWORDS:
            for engine in ["bing", "duckduckgo"]:
                # Bing: halaman 1 doang (paging nggak support).
                # DuckDuckGo: halaman 1-2, stop kalau kosong / CAPTCHA.
                pages = [1, 2] if engine == "duckduckgo" else [1]
                for p in pages:
                    stats["queries"] += 1
                    try:
                        d = searxng_search(q, engine, p)
                    except Exception as e:
                        print(f"[{time.time()-start:5.1f}s] {q!r} {engine} p{p}: ERROR {e}", flush=True)
                        break
                    results = d.get("results", [])
                    unresp = d.get("unresponsive_engines") or []
                    if unresp:
                        print(f"[{time.time()-start:5.1f}s] {q!r} {engine} p{p}: "
                              f"unresponsive={unresp} -> pindah engine", flush=True)
                        break
                    if not results:
                        break
                    for res in results:
                        u = res.get("url")
                        if not u or u in seen:
                            continue
                        seen.add(u)
                        stats["raw"] += 1
                        title = res.get("title") or ""
                        snippet = res.get("content") or ""
                        kind = classify(u, title, snippet)
                        # simpan dulu sebagai candidate (dedupe via DB API)
                        is_new = db.save_candidate({
                            "url": u, "canonical": canonical(u), "kind": kind,
                            "status": "candidate", "score": 0,
                            "title": title, "snippet": snippet[:300],
                            "evidence": "", "source": f"searxng:{engine}",
                            "created_at": time.time(), "yara_rules": "", "method": "",
                        })
                        if not is_new:
                            continue  # URL udah ada dari run sebelumnya
                        stats["new"] += 1
                        if kind == "injected":
                            stats["injected"] += 1
                        # --- whitelist: jelas bukan judol, buang tanpa fetch ---
                        if is_whitelisted(u):
                            db.update(u, status="discarded", score=0, method="whitelist")
                            stats["discarded"] += 1
                            continue
                        # --- verifikasi: fetch path lengkapnya + YARA ---
                        try:
                            v = verify(u, kind)
                        except Exception:
                            db.update(u, status="discarded")
                            stats["discarded"] += 1
                            continue
                        if v["verified"]:
                            db.update(u, status="verified", score=v["score"],
                                      evidence=v["evidence"][:500],
                                      yara_rules=",".join(v["yara_rules"]),
                                      method=v["method"])
                            stats["verified"] += 1
                            if v["yara_rules"]:
                                stats["yara"] += 1
                        else:
                            db.update(u, status="discarded", score=v["score"],
                                      yara_rules=",".join(v["yara_rules"]), method="")
                            stats["discarded"] += 1
                    print(f"[{time.time()-start:5.1f}s] {q!r} {engine} p{p}: "
                          f"results={len(results)} total_unik={len(seen)} "
                          f"verified={stats['verified']} discarded={stats['discarded']}", flush=True)
                    time.sleep(DELAY)
    except KeyboardInterrupt:
        # Ctrl+C: keluar dari loop, lanjut ke ringkasan di bawah.
        # Semua yang udah diproses SUDAH di-commit ke DB per URL.
        print("\n\n[Ctrl+C] Berhenti atas permintaan user. Menyimpan ringkasan...")

    elapsed = time.time() - start
    print(f"\nSELESAI dalam {elapsed:.1f}s | queries={stats['queries']} "
          f"| URL unik={len(seen)} | baru masuk DB={stats['new']} "
          f"| injected={stats['injected']}")
    print(f"verified={stats['verified']} (YARA match: {stats['yara']}) | discarded={stats['discarded']} | DB: {db.path}")
    print("Lihat yang verified:  python3 -c \"import json; [print(r['url'], r['kind'], r.get('yara_rules',''), r.get('method','')) for r in map(json.loads, open('"
          + db.path + "')) if r['status']=='verified']\"")
    print("Lihat yang injected:  grep '\"kind\": \"injected\"' " + db.path)
    db.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())

