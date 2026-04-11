-- DDAS v2 — Database Schema (DDL Mirror, Schema Version 2)
-- Single-algorithm design: BLAKE3 exclusively.
-- Updated: 2026-03-05
--
-- Change log:
--   v1 → v2: Removed hash_algo, extension, scan_state columns.
--            Partial index strategy preserved for size, partial_hash, full_hash.
--
-- Pipeline: size → partial_hash → full_hash
--
-- Column reference:
--   id            Primary key, autoincrement
--   path          Absolute file path, UNIQUE per file
--   size          File size in bytes; Stage 1 filter
--   partial_hash  BLAKE3 of first 128 KB + last 128 KB; Stage 2 filter
--   full_hash     BLAKE3 of entire file; Stage 3 confirmation
--   last_modified Unix timestamp of file mtime at indexing time
--   indexed_at    Unix timestamp when DDAS last updated this record

CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    path          TEXT    NOT NULL UNIQUE,
    size          INTEGER NOT NULL DEFAULT 0,
    partial_hash  TEXT             DEFAULT NULL,
    full_hash     TEXT             DEFAULT NULL,
    last_modified INTEGER NOT NULL DEFAULT 0,
    indexed_at    INTEGER NOT NULL DEFAULT 0
);

-- ── Indexes ────────────────────────────────────────────────────────────────

-- Stage 1: size equality — rejects most unique files before any hashing
CREATE INDEX IF NOT EXISTS idx_size
    ON files(size);

-- Stage 2: partial hash filter
--   Partial index: only rows with a computed partial hash are included,
--   keeping the index small and hot in the page cache.
CREATE INDEX IF NOT EXISTS idx_partial_hash
    ON files(partial_hash)
    WHERE partial_hash IS NOT NULL;

-- Stage 3: full hash confirmation + UI duplicate grouping
CREATE INDEX IF NOT EXISTS idx_full_hash
    ON files(full_hash)
    WHERE full_hash IS NOT NULL;

-- Reconciliation: path lookup during startup filesystem diff
CREATE INDEX IF NOT EXISTS idx_path
    ON files(path);
