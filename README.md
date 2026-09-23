# FraudHound v0.2

Graph-powered agentic fraud investigation and next-best-action prototype.

## What is implemented

- FastAPI backend with a real investigation loop.
- SQLite case/audit persistence.
- Pluggable graph adapter: `MockGraphAdapter` for local/demo use and `TigerGraphAdapter` for production.
- Deterministic evidence-grounded fraud pattern detection.
- Separate risk, confidence, and uncertainty.
- Controlled evidence-request and reassessment loop.
- Policy/permission engine and approval gates.
- Persistent case memory and similar-case retrieval.
- GraphRAG-style context builder for graph + policy + historical case evidence.
- Demo scenarios: high-confidence fraud, ambiguous fraud that changes after evidence, legitimate transaction.
- Benchmark runner that reads benchmark cases from the configured dataset instead of hardcoding labels.
- Dark analyst dashboard served by FastAPI.

## Important dataset rule

The repository does **not** include HHGOA_IEEE. Put the supplied hackathon dataset under `data/HHGOA_IEEE/` or set `HHGOA_DATA_DIR` to its location. The ingestion/discovery code reads the dataset README and records the discovered schema. It does not use hidden benchmark labels as an investigation feature.

## Run locally

```bash
cd fraudhound-v0.2
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python scripts/discover_dataset.py
uvicorn backend.main:app --reload
```

Open http://127.0.0.1:8000

## Demo mode

The UI includes three deterministic demo cases. They use the same tool interfaces as the production graph adapter. The ambiguous case demonstrates:

`HIGH risk + LOW confidence -> request step-up -> evidence arrives -> MEDIUM risk + HIGH confidence -> allow/monitor`

## Benchmark

```bash
python run_benchmark.py
```

Outputs are written to `outputs/case_*.json`. If the benchmark directory is not available, the runner exits with a clear dataset message instead of fabricating results.

## TigerGraph

Set:

```env
TIGERGRAPH_URL=https://<host>
TIGERGRAPH_GRAPH=HHGOA_IEEE
TIGERGRAPH_TOKEN=<token>
```

Then select `GRAPH_BACKEND=tigergraph`. `backend/graph/tigergraph_adapter.py` exposes the same interface used by the agent, so the controller is not coupled to TigerGraph transport details. The GSQL schema and starter queries live in `backend/graph/`.

TigerGraph MCP can be connected externally; the agent tool layer is intentionally registry-based so the LLM never gets arbitrary API access.

## Architecture

```text
Signal -> Agent Controller -> Graph/Policy/Memory Tools
                         -> Evidence synthesis
                         -> Risk + confidence + uncertainty
                         -> Evidence request? -> reassess
                         -> Next best action -> policy/approval
                         -> execute/simulate -> case memory + audit
```

## Safety/benchmark integrity

- LLM output is treated as reasoning, never as raw evidence.
- Evidence has explicit source and provenance.
- Actions are checked against a registry and policy engine.
- Historical cases are contextual evidence, not ground truth.
- No hidden benchmark label is exposed to the agent.
- Every tool invocation and material state transition is auditable.
