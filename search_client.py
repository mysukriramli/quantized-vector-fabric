#!/usr/bin/env python3
import re
import math
import hashlib
import duckdb

VECTOR_DIM = 128
PROJECTION_SEED = 42

def project_query_to_bits(query: str, dim: int = VECTOR_DIM) -> int:
    tokens = re.findall(r"\w+", query.lower())
    if not tokens:
        return 0
    raw_dense = [0.0] * dim
    for token in tokens:
        for i in range(dim):
            h_in = f"{PROJECTION_SEED}_{token}_{i}".encode("utf-8")
            digest = hashlib.md5(h_in).digest()
            val = ((digest[0] % 3) - 1)
            raw_dense[i] += float(val)

    packed_int = 0
    for i in range(dim):
        if raw_dense[i] > 0:
            packed_int |= (1 << i)
    return packed_int

def local_semantic_search(parquet_file: str, query: str, top_k: int = 5):
    query_bits = project_query_to_bits(query)
    conn = duckdb.connect()

    records = conn.execute(f"SELECT doc_id, source_wire, title, summary, bit_packed_hex FROM '{parquet_file}'").fetchall()

    scored = []
    for r in records:
        doc_id, wire, title, summary, bit_hex = r
        doc_bits = int(bit_hex, 16)
        # Fast Hamming Distance via bitwise XOR & popcount
        xor_diff = query_bits ^ doc_bits
        distance = bin(xor_diff).count("1")
        similarity = 1.0 - (distance / VECTOR_DIM)
        scored.append((similarity, doc_id, wire, title, summary))

    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[:top_k]

if __name__ == "__main__":
    import sys
    q = sys.argv[1] if len(sys.argv) > 1 else "malicious pyyaml package remote code execution"
    p = "public/vectors.parquet"
    print(f"Executing zero-token local search for: '{q}'")
    results = local_semantic_search(p, q)
    for score, doc_id, wire, title, summary in results:
        print(f"[{score:.2%}] {title} ({wire}) - {summary[:100]}...")
