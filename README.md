# FraudHound v0.3 — Agentic Fraud Investigation + Blockchain Audit

FraudHound is a hackathon prototype for graph-powered fraud investigation. It separates deterministic evidence gathering from agent reasoning and adds an append-only blockchain-style integrity layer.

## What changed in v0.3

- Guided in-app **FraudHound Academy** tutorial before the analyst workspace.
- Functional investigation lab with demo scenarios.
- Risk and confidence shown separately.
- Evidence-request / reassessment loop.
- TigerGraph-compatible graph adapter plus deterministic mock adapter.
- Persistent SQLite case memory.
- Policy and approval gate.
- **Blockchain audit layer:** SHA-256 hash-chained events, verification endpoint, case anchoring, and UI audit view.
- Blockchain stores hashes and metadata, not raw PII or transaction payloads.

## Architecture

```text
HHGOA_IEEE / future production data
            |
            v
       TigerGraph
            |
            v
    Investigation Tools
            |
      +-----+------+
      |            |
   Case Memory   Policy/RAG
      |            |
      +-----+------+
            v
      Agent Controller
            |
     Risk + Confidence
            |
     More evidence?
       /        \
     yes         no
      |           |
 Evidence      NBA
      |           |
      +-----+-----+
            v
      Approval Gate
            |
      Execute/Simulate
            |
            v
   Blockchain Audit Layer
            |
            v
      Analyst Dashboard
```

## Run locally

Create a virtual environment first:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn backend.main:app --reload
```

Open `http://127.0.0.1:8000`.

## Important dataset note

The repository intentionally does not invent or bundle HHGOA_IEEE benchmark answers. Put the supplied dataset under `data/HHGOA_IEEE/` or set `HHGOA_DATA_DIR`. Run:

```bash
python scripts/discover_dataset.py
```

before implementing the production ingestion mapping.

## Blockchain design

`backend/blockchain/ledger.py` implements a local append-only adapter. Each event contains:

- event type
- payload SHA-256
- previous block hash
- block hash
- timestamp
- case ID

Use the interface as the seam for a permissioned production ledger such as Hyperledger Fabric. Do not put raw customer PII on-chain.

## API additions

```text
GET  /api/cases/{case_id}/blockchain
POST /api/cases/{case_id}/blockchain/anchor
GET  /api/blockchain/verify/{case_id}
```

## Tutorial flow

The UI intentionally opens in **FraudHound Academy**. Complete the lessons, launch the ambiguous scenario, submit simulated step-up authentication, inspect the reassessment, then open Blockchain Audit to verify the case chain.
