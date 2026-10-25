CREATE SEQUENCE IF NOT EXISTS seq_commit_id START 1;

CREATE TABLE IF NOT EXISTS vector_registry (
    doc_id VARCHAR PRIMARY KEY,
    source_wire VARCHAR,
    title VARCHAR,
    summary VARCHAR,
    dimension INTEGER,
    quantization_type VARCHAR,
    int8_vector VARCHAR,
    bit_packed_hex VARCHAR,
    content_hash VARCHAR,
    indexed_at_utc VARCHAR
);

CREATE TABLE IF NOT EXISTS vector_ledger (
    commit_id BIGINT PRIMARY KEY,
    timestamp_utc VARCHAR,
    operation VARCHAR,
    doc_id VARCHAR,
    source_wire VARCHAR,
    detail VARCHAR
);
