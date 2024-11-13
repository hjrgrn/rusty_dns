-- Add migration script here
-- TODO: limit everything
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY,
    address VARCHAR(15),
    host VARCHAR(256),
    priority INTEGER,
    domain VARCHAR(256) NOT NULL,
    expiration_date TIMESTAMP NOT NULL,
    ttl TIMESTAMP NOT NULL,
    record_type INTEGER
);
