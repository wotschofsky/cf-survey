CREATE TABLE IF NOT EXISTS default.requests (
    ip_hash String,
    ray String,
    pop String MATERIALIZED splitByChar('-', ray)[2],
    country String,
    isp String,
    timestamp DateTime
) ENGINE = MergeTree()
ORDER BY timestamp;
