import os
import re
import json
import math
import hashlib
import duckdb
import requests
from datetime import datetime, timezone

DB_FILE = "data/vector_fabric.db"
HISTORY_DIR = "data/history"
EXPORT_DIR = "public"
API_DIR = os.path.join(EXPORT_DIR, "v1")

VECTOR_DIM = 128
PROJECTION_SEED = 42

WIRE_FEEDS = {
    "package_compromise": "https://mysukriramli.github.io/package-compromise-wire/v1/active-alerts.json",
    "epss_kev": "https://mysukriramli.github.io/epss-kev-delta-wire/v1/high-risk-exploited.json",
    "standards_drift": "https://mysukriramli.github.io/standards-drift-wire/v1/recent-standards.json"
}

def deterministic_projection(text: str, dim: int = VECTOR_DIM) -> tuple[list[int], str]:
    tokens = re.findall(r"\w+", text.lower())
    if not tokens:
        return [0] * dim, "00" * (dim // 8)

    raw_dense = [0.0] * dim
    for token in tokens:
        for i in range(dim):
            h_in = f"{PROJECTION_SEED}_{token}_{i}".encode("utf-8")
            digest = hashlib.md5(h_in).digest()
            val = ((digest[0] % 3) - 1)
            raw_dense[i] += float(val)

    norm = math.sqrt(sum(x * x for x in raw_dense))
    if norm > 0:
        raw_dense = [x / norm for x in raw_dense]

    int8_vec = [max(-127, min(127, int(x * 127.0))) for x in raw_dense]

    packed_bytes = bytearray(dim // 8)
    for i in range(dim):
        if int8_vec[i] > 0:
            byte_idx = i // 8
            bit_idx = i % 8
            packed_bytes[byte_idx] |= (1 << bit_idx)

    return int8_vec, packed_bytes.hex()

def compute_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()

def harvest_upstream_documents() -> list[dict]:
    documents = []
    headers = {"User-Agent": "QuantizedVectorFabric/1.0"}

    # 1. Package Compromises
    try:
        r = requests.get(WIRE_FEEDS["package_compromise"], headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("alerts", [])
            for item in data[:60]:
                doc_id = f"pkg_{item.get('event_id', '')}"
                title = f"{item.get('ecosystem')}/{item.get('package_name')}"
                summary = item.get("summary", "")
                documents.append({
                    "doc_id": doc_id,
                    "source_wire": "package-compromise-wire",
                    "title": title,
                    "summary": summary,
                    "search_text": f"{title} {summary}"
                })
    except Exception as e:
        print(f"Notice: Package wire harvest skipped ({e})")

    # 2. EPSS KEV Threats
    try:
        r = requests.get(WIRE_FEEDS["epss_kev"], headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("vulnerabilities", [])
            for item in data[:60]:
                cve = item.get("cve_id", "")
                doc_id = f"kev_{cve}"
                title = f"{cve} - {item.get('vendor_project')} {item.get('product')}"
                summary = f"{item.get('vulnerability_name')}. {item.get('short_description', '')}"
                documents.append({
                    "doc_id": doc_id,
                    "source_wire": "epss-kev-delta-wire",
                    "title": title,
                    "summary": summary,
                    "search_text": f"{title} {summary}"
                })
    except Exception as e:
        print(f"Notice: EPSS KEV harvest skipped ({e})")

    # 3. Standards Drift
    try:
        r = requests.get(WIRE_FEEDS["standards_drift"], headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("standards", [])
            for item in data[:60]:
                doc_id = f"std_{item.get('doc_id', '')}"
                title = f"{item.get('doc_id')} {item.get('title')}"
                summary = f"Status: {item.get('current_status')}. Area: {item.get('area')} Stream: {item.get('stream')}"
                documents.append({
                    "doc_id": doc_id,
                    "source_wire": "standards-drift-wire",
                    "title": title,
                    "summary": summary,
                    "search_text": f"{title} {summary}"
                })
    except Exception as e:
        print(f"Notice: Standards harvest skipped ({e})")

    return documents

def build_static_api(conn):
    os.makedirs(API_DIR, exist_ok=True)
    now_iso = datetime.now(timezone.utc).isoformat()

    cur = conn.execute("SELECT doc_id, source_wire, title, summary, dimension, bit_packed_hex, indexed_at_utc FROM vector_registry ORDER BY indexed_at_utc DESC")
    cols = [desc[0] for desc in cur.description]
    all_vectors = [dict(zip(cols, row)) for row in cur.fetchall()]

    with open(os.path.join(API_DIR, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "updated_at": now_iso,
                "dimension": VECTOR_DIM,
                "quantization": "1-bit_packed_and_int8",
                "projection_seed": PROJECTION_SEED,
                "total_shards": len(all_vectors)
            },
            "vectors": all_vectors
        }, f, indent=2)

    lines = [
        "# Quantized Vector Fabric",
        f"> Last Sync: {now_iso} UTC",
        f"> Architecture: 128-dim pre-quantized embeddings (INT8 & 16-byte packed bitvectors).",
        "> Zero-Token Semantic Retrieval: Query locally via Hamming distance in < 5ms without external Vector DBs.",
        "",
        "## Indexed Vector Shards Sample"
    ]
    for v in all_vectors[:20]:
        lines.append(f"- **{v['title']}** (`{v['source_wire']}`): BitHex: `{v['bit_packed_hex']}`")

    with open(os.path.join(EXPORT_DIR, "llms.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    html = f"""<!DOCTYPE html><html><head><title>Quantized Vector Fabric</title></head>
    <body style='font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;line-height:1.6;padding:0 1rem;'>
    <h1>⚡ Quantized Vector Fabric</h1>
    <p>Zero-token-cost semantic search fabric committing pre-quantized vector indices for autonomous AI agents.</p>
    <h3>Machine Feeds</h3>
    <ul>
      <li><a href='v1/manifest.json'>/v1/manifest.json</a> (Vector Manifest &amp; 16-Byte BitHex Keys)</li>
      <li><a href='vectors.parquet'>vectors.parquet</a> (Columnar Vector Database with INT8 &amp; BitVectors)</li>
      <li><a href='search_client.py'>search_client.py</a> (Microsecond Local Search Client)</li>
      <li><a href='llms.txt'>llms.txt</a> (Token-Efficient LLM Digest)</li>
    </ul>
    <h3>Vector Index Statistics</h3>
    <p>Total Indexed Documents: <strong>{len(all_vectors)}</strong> | Dimension: <strong>{VECTOR_DIM}</strong> | Bitvector Size: <strong>16 bytes/record</strong></p>
    </body></html>"""
    with open(os.path.join(EXPORT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)

def run():
    os.makedirs("data", exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(EXPORT_DIR, exist_ok=True)

    conn = duckdb.connect(DB_FILE)
    with open("schema.sql", "r", encoding="utf-8") as f:
        conn.execute(f.read())

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    date_str = now.strftime("%Y-%m-%d")
    year_str = now.strftime("%Y")
    month_str = now.strftime("%m")

    month_dir = os.path.join(HISTORY_DIR, year_str, month_str)
    os.makedirs(month_dir, exist_ok=True)
    daily_history_file = os.path.join(month_dir, f"{date_str}.jsonl")

    documents = harvest_upstream_documents()

    conn.execute("BEGIN TRANSACTION")

    for doc in documents:
        d_id = doc["doc_id"]
        wire = doc["source_wire"].replace("'", "''")
        title = doc["title"].replace("'", "''")
        summary = doc["summary"].replace("'", "''")

        int8_vec, bit_hex = deterministic_projection(doc["search_text"], VECTOR_DIM)
        vec_json = json.dumps(int8_vec)

        h_payload = {"id": d_id, "bit_hex": bit_hex, "title": title}
        content_hash = compute_hash(h_payload)

        existing = conn.execute(f"SELECT content_hash FROM vector_registry WHERE doc_id = '{d_id}'").fetchone()

        if not existing:
            conn.execute(f"""
                INSERT INTO vector_registry (
                    doc_id, source_wire, title, summary, dimension,
                    quantization_type, int8_vector, bit_packed_hex,
                    content_hash, indexed_at_utc
                ) VALUES (
                    '{d_id}', '{wire}', '{title}', '{summary}', {VECTOR_DIM},
                    'INT8_AND_1BIT', '{vec_json}', '{bit_hex}',
                    '{content_hash}', '{now_iso}'
                )
            """)

            commit_id = conn.execute("SELECT nextval('seq_commit_id')").fetchone()[0]
            conn.execute(f"""
                INSERT INTO vector_ledger (commit_id, timestamp_utc, operation, doc_id, source_wire, detail)
                VALUES ({commit_id}, '{now_iso}', 'INDEX_VECTOR', '{d_id}', '{wire}', 'Initial quantized vector generated')
            """)

            entry = {
                "commit_id": commit_id, "timestamp_utc": now_iso, "operation": "INDEX_VECTOR",
                "doc_id": d_id, "wire": wire, "bit_hex": bit_hex
            }
            with open(daily_history_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

        elif existing[0] != content_hash:
            conn.execute(f"""
                UPDATE vector_registry SET
                    title = '{title}',
                    summary = '{summary}',
                    int8_vector = '{vec_json}',
                    bit_packed_hex = '{bit_hex}',
                    content_hash = '{content_hash}',
                    indexed_at_utc = '{now_iso}'
                WHERE doc_id = '{d_id}'
            """)

            commit_id = conn.execute("SELECT nextval('seq_commit_id')").fetchone()[0]
            conn.execute(f"""
                INSERT INTO vector_ledger (commit_id, timestamp_utc, operation, doc_id, source_wire, detail)
                VALUES ({commit_id}, '{now_iso}', 'VECTOR_UPDATE', '{d_id}', '{wire}', 'Quantized vector refreshed')
            """)

            entry = {
                "commit_id": commit_id, "timestamp_utc": now_iso, "operation": "VECTOR_UPDATE",
                "doc_id": d_id, "wire": wire, "bit_hex": bit_hex
            }
            with open(daily_history_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    conn.execute("COMMIT")

    conn.execute(f"COPY (SELECT doc_id, source_wire, title, summary, dimension, bit_packed_hex, int8_vector, indexed_at_utc FROM vector_registry) TO '{EXPORT_DIR}/vectors.parquet' (FORMAT PARQUET)")
    build_static_api(conn)
    conn.close()

if __name__ == "__main__":
    run()
