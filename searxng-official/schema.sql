-- schema.sql — Skema DB bersama IMPHNEN (Turso/libSQL, juga jalan di SQLite lokal)
-- Dipakai 3 orang: Isya (search+scraper), Daffa (infra+verification), Gustav (lead+submit)
-- Status flow: candidate -> verified -> queued -> submitted
-- Satu baris = satu URL kanonik. Duplikat ditolak oleh PRIMARY KEY (url).
-- Dibuat 28 Nov 2026, disiapkan sebelum techmeet Jumat 4 Des 2026
-- (saat itu baru dikasih akses DeepSeek Netra; DB disiapkan dulu supaya
--  5 Des tinggal submit, bukan setup).

CREATE TABLE IF NOT EXISTS candidates (
    url         TEXT PRIMARY KEY,          -- URL lengkap (path ikut, bukan homepage doang)
    canonical   TEXT NOT NULL,             -- bentuk kanonik (tanpa http/https, www, query, #)
    kind        TEXT NOT NULL DEFAULT 'biasa',  -- 'biasa' | 'injected'
    status      TEXT NOT NULL DEFAULT 'candidate', -- candidate|verified|queued|submitted|discarded
    score       INTEGER NOT NULL DEFAULT 0,
    title       TEXT DEFAULT '',
    snippet     TEXT DEFAULT '',
    evidence    TEXT DEFAULT '',
    source      TEXT DEFAULT '',           -- keyword / engine asal (mis. 'slot gacor / bing')
    yara_rules  TEXT DEFAULT '',           -- 'Judol_1,Judol_4' atau ''
    method      TEXT DEFAULT '',           -- '' | keyword | yara | yara+keyword | whitelist | llm
    llm_verdict TEXT DEFAULT '',           -- '' | JUDOL | ARTIKEL | BUKAN
    llm_reason  TEXT DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Antrean submit: yang verified dulu, YARA dulu, score tertinggi dulu
CREATE INDEX IF NOT EXISTS idx_queue
    ON candidates (status, yara_rules, score DESC);

CREATE INDEX IF NOT EXISTS idx_canonical ON candidates (canonical);
CREATE INDEX IF NOT EXISTS idx_kind_status ON candidates (kind, status);
