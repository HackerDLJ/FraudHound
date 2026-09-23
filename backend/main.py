from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from backend.agent.controller import FraudHoundController
from backend.blockchain.ledger import AuditLedger
from backend.graph.mock_adapter import MockGraphAdapter
from backend.graph.tigergraph_adapter import TigerGraphAdapter
from backend.memory.case_memory import CaseMemory
from backend.models.schemas import *


load_dotenv()

BASE = Path(__file__).resolve().parents[1]

mem = CaseMemory(
    os.getenv(
        "DATABASE_PATH",
        str(BASE / "data/fraudhound.db"),
    )
)

backend = os.getenv("GRAPH_BACKEND", "mock").lower()

graph = (
    TigerGraphAdapter()
    if backend == "tigergraph"
    else MockGraphAdapter()
)

controller = FraudHoundController(graph, mem)

ledger = AuditLedger(
    os.getenv(
        "DATABASE_PATH",
        str(BASE / "data/fraudhound.db"),
    )
)

app = FastAPI(
    title="FraudHound v0.3",
    version="0.3.0-blockchain",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "graph_backend": backend,
        "blockchain_backend": "hash-chained-local-ledger",
        "version": "0.3.0-blockchain",
    }


@app.get("/api/cases")
def cases():
    return mem.list()


@app.post("/api/investigations")
def investigations(req: InvestigationRequest):
    if req.scenario and hasattr(graph, "select_scenario"):
        graph.select_scenario(req.scenario)

    case = controller.create_case(req)

    ledger.append(
        case.case_id,
        "CASE_CREATED",
        {"trigger": case.trigger},
    )

    case = controller.investigate(case)

    mem.save(case)

    ledger.append(
        case.case_id,
        "INVESTIGATION_STATE",
        case.model_dump(),
        {
            "risk": (
                case.risk_assessment.risk_score
                if case.risk_assessment
                else None
            )
        },
    )

    return case


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    x = mem.get(case_id)

    if not x:
        raise HTTPException(404, "Case not found")

    return x


@app.post("/api/cases/{case_id}/investigate")
def investigate(case_id: str):
    x = mem.get(case_id)

    if not x:
        raise HTTPException(404, "Case not found")

    case = Case.model_validate(x)

    return controller.investigate(case)


@app.post("/api/cases/{case_id}/evidence")
def evidence(
    case_id: str,
    body: EvidenceInput,
):
    x = mem.get(case_id)

    if not x:
        raise HTTPException(404, "Case not found")

    case = controller.receive_evidence(
        Case.model_validate(x),
        body,
    )

    ledger.append(
        case_id,
        "EVIDENCE_RECEIVED",
        body.model_dump(),
        {
            "risk_after": (
                case.risk_assessment.risk_score
                if case.risk_assessment
                else None
            )
        },
    )

    return case


@app.post("/api/cases/{case_id}/approve")
def approve(
    case_id: str,
    body: ApprovalInput,
):
    x = mem.get(case_id)

    if not x:
        raise HTTPException(404, "Case not found")

    case = controller.approve(
        Case.model_validate(x),
        body.approved,
        body.approver,
        body.note,
    )

    ledger.append(
        case_id,
        "APPROVAL_DECISION",
        body.model_dump(),
        {"status": case.status},
    )

    return case


@app.post("/api/cases/{case_id}/action")
def action(
    case_id: str,
    body: ActionInput,
):
    x = mem.get(case_id)

    if not x:
        raise HTTPException(404, "Case not found")

    try:
        return controller.execute(
            Case.model_validate(x),
            body.action,
        )
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.get("/api/cases/{case_id}/graph")
def graph_view(case_id: str):
    x = mem.get(case_id)

    if not x:
        raise HTTPException(404, "Case not found")

    tx = x["transactions"][0]["transaction_id"]

    return graph.get_graph_neighborhood(
        tx,
        2,
    )


@app.get("/api/cases/{case_id}/similar")
def similar(case_id: str):
    x = mem.get(case_id)

    if not x:
        raise HTTPException(404, "Case not found")

    return x.get("similar_cases", [])


@app.get("/api/cases/{case_id}/timeline")
def timeline(case_id: str):
    x = mem.get(case_id)

    if not x:
        raise HTTPException(404, "Case not found")

    return x.get("timeline", [])


@app.get("/api/cases/{case_id}/blockchain")
def blockchain(case_id: str):
    x = mem.get(case_id)

    if not x:
        raise HTTPException(404, "Case not found")

    return {
        "events": ledger.list(case_id),
        "verification": ledger.verify(case_id),
    }


@app.get("/api/cases/{case_id}/blockchain/status")
def blockchain_status(case_id: str):
    x = mem.get(case_id)

    if not x:
        raise HTTPException(404, "Case not found")

    return ledger.chain_status(case_id)


@app.post("/api/cases/{case_id}/blockchain/anchor")
def anchor(case_id: str):
    x = mem.get(case_id)

    if not x:
        raise HTTPException(404, "Case not found")

    payload = {
        "case_id": case_id,
        "risk": x.get("risk_assessment"),
        "patterns": x.get("patterns", []),
        "recommendation": x.get(
            "recommended_actions",
            [],
        ),
        "outcome": x.get("outcome"),
    }

    return ledger.append(
        case_id,
        "CASE_ANCHORED",
        payload,
        {"purpose": "case_integrity"},
    )


@app.get("/api/blockchain/verify/{case_id}")
def verify_blockchain(case_id: str):
    if not mem.get(case_id):
        raise HTTPException(404, "Case not found")

    return ledger.verify(case_id)


@app.post("/api/benchmark/run")
def benchmark():
    from backend.benchmark.runner import run_benchmark

    return run_benchmark(controller)


@app.get("/")
def index():
    return FileResponse(
        BASE / "frontend/index.html"
    )


@app.get("/{path:path}")
def static(path: str):
    p = BASE / "frontend" / path

    if p.exists() and p.is_file():
        return FileResponse(p)

    return FileResponse(
        BASE / "frontend/index.html"
    )