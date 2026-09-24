# FraudHound v3.0
## Agentic Fraud Investigation + Graph Intelligence + Blockchain Audit

FraudHound is an agentic fraud investigation platform designed to help analysts investigate suspicious financial activity, connect related entities, gather structured evidence, reason over that evidence, and recommend controlled next-best actions.

The system combines:

- Graph-powered investigation
- Fraud-ring intelligence
- Deterministic risk and policy logic
- Controlled agent reasoning
- Optional LLM reasoning
- Strict tool and argument validation
- Human approval gates
- Persistent case memory
- Blockchain-style audit integrity
- Analyst-facing investigation workflows

FraudHound is designed around a core principle:

> **AI may reason over evidence, but deterministic controls remain authoritative over actions.**

---

# What is new in v3.0?

FraudHound v3.0 extends the original investigation workflow with a controlled agentic reasoning architecture.

### Core additions

- **Fraud-ring detection**
  - Detects connected account clusters.
  - Correlates shared devices, IP addresses, transactions, and historical fraud associations.
  - Produces structured ring evidence with confidence and explanations.

- **Controlled reasoning boundary**
  - Separates reasoning from authoritative investigation and action logic.
  - Reasoning can recommend the next investigation tool.
  - The deterministic controller remains authoritative over risk, policy, approval, and execution.

- **LLM reasoning provider**
  - Supports an injected LLM client through a controlled provider boundary.
  - LLM output is parsed and validated before it can influence the investigation workflow.
  - Invalid or unsafe responses fall back to deterministic reasoning.

- **Tool registry**
  - Every investigation tool is explicitly registered.
  - Required arguments and optional arguments are validated.
  - Argument types and constrained values are checked before execution.
  - Unknown tools and unexpected arguments are rejected.

- **Agent safety evaluation**
  - Tests malicious tool selection.
  - Tests malformed LLM output.
  - Tests unauthorized fields.
  - Tests direct action-command injection.
  - Tests SQL/GSQL tool rejection.
  - Tests tool execution isolation.

- **GraphRAG-style evidence context**
  - Reasoning receives compact structured graph evidence rather than unrestricted raw data access.
  - Evidence includes provenance and investigation context.

- **Blockchain audit integrity**
  - Investigation events are recorded in a hash-chained append-only ledger.
  - Case audit chains can be verified independently.
  - Raw customer PII and transaction payloads are not placed on-chain.

---

# Architecture

```text
                    Investigation Data
                           |
                           v
                    +-------------+
                    | TigerGraph  |
                    | / Graph     |
                    | Adapter     |
                    +-------------+
                           |
                           v
                 +---------------------+
                 | Investigation Tools |
                 +---------------------+
                           |
                           v
                 +---------------------+
                 |   Tool Registry     |
                 |---------------------|
                 | Registered tools    |
                 | Required arguments  |
                 | Type validation     |
                 | Argument validation |
                 +---------------------+
                           |
                           v
                  +----------------+
                  | Case / Graph   |
                  | Evidence       |
                  +----------------+
                           |
             +-------------+-------------+
             |                           |
             v                           v
     Fraud-Ring Detection        Pattern Detection
             |                           |
             +-------------+-------------+
                           |
                           v
                  +----------------+
                  | Risk +         |
                  | Confidence     |
                  +----------------+
                           |
                           v
                  +----------------+
                  | Reasoning      |
                  | Boundary       |
                  +----------------+
                     |          |
          +----------+          +----------+
          |                                |
          v                                v
 Deterministic Provider             LLM Provider
          |                                |
          +---------------+----------------+
                          |
                          v
                  Validated Recommendation
                          |
                          v
                  Deterministic Controller
                          |
             +------------+-------------+
             |                          |
             v                          v
        More Evidence?             Next Action
             |                          |
             v                          v
       Evidence Loop             Policy Engine
                                        |
                                        v
                                  Approval Gate
                                        |
                                        v
                                  Action Execution
                                        |
                                        v
                              Blockchain Audit Ledger
                                        |
                                        v
                                Analyst Dashboard