-- Geo matchers for split-horizon views (require a GeoLite2 database at runtime).
-- Stored as JSON arrays, matching the `networks` column convention.
ALTER TABLE views ADD COLUMN countries  TEXT NOT NULL DEFAULT '[]';
ALTER TABLE views ADD COLUMN continents TEXT NOT NULL DEFAULT '[]';
ALTER TABLE views ADD COLUMN asns       TEXT NOT NULL DEFAULT '[]';
