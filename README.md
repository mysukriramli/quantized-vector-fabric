# ⚡ Quantized Vector Fabric

An autonomous data plane running on GitHub Actions that generates and commits pre-quantized 1-bit and INT8 vector embeddings into Parquet shards directly alongside telemetry wires.

## Performance & Token Savings
- **Zero Embedding API Fees**: Consumer agents perform local random-projection matching.
- **Zero Vector DB Hosting**: Entire dataset fits into a 50 KB `.parquet` file.
- **Latency**: Local Hamming distance matching runs in under 5 milliseconds via DuckDB / Bitwise XOR.

## Machine Feeds
- [`v1/manifest.json`](public/v1/manifest.json) (Vector manifest & metadata)
- [`search_client.py`](public/search_client.py) (Reference client)
- [`llms.txt`](public/llms.txt) (Token-efficient LLM digest)
- `vectors.parquet` (Columnar Parquet database with INT8 & packed bitvectors)

## Architecture
- **Projection Model**: Deterministic locality-sensitive random projection (128-dim)
- **Quantization**: Signed 8-bit integers (`int8`) + Packed 16-byte bitvectors (`uint8[16]`)
- **Database**: DuckDB + Parquet
- **Ledger**: Append-only Git-committed JSONL in `/data/history`
- **Edge CDN**: GitHub Pages (Fastly CDN)
