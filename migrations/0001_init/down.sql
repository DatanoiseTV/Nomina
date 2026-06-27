-- Drop in FK-safe order: children before parents.
DROP TABLE IF EXISTS secondary_zones;
DROP TABLE IF EXISTS dnssec_keys;
DROP TABLE IF EXISTS records;
DROP TABLE IF EXISTS blocklist_entries;
DROP TABLE IF EXISTS dyndns_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS query_log;
DROP TABLE IF EXISTS conditional_forwards;
DROP TABLE IF EXISTS rewrites;
DROP TABLE IF EXISTS block_rules;
DROP TABLE IF EXISTS blocklists;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS zones;
DROP TABLE IF EXISTS views;
DROP TABLE IF EXISTS users;
