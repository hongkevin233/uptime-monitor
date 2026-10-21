CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  ok INTEGER NOT NULL,
  status INTEGER,
  latency_ms INTEGER,
  error TEXT,
  probe TEXT NOT NULL DEFAULT 'cf',
  colo TEXT NOT NULL DEFAULT '',
  ts INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_checks_target_ts ON checks(target, ts);
CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts);
