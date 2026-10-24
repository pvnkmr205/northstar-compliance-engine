# Northstar Privacy Compliance Audit — Telemetry & Resource Report

## 1. Operational Telemetry
- **Evaluation Timestamp:** 2026-10-25 03:00:00 UTC
- **Total Runtime:** 79.20 seconds
- **Throughput:** ~6.54 cases / second
- **Mean Latency:** 152.9 ms per case
- **Architecture:** Zero-token deterministic Python runtime with embedded SQLite cache

## 2. Model Harnesses & Development Accounting
| Harness / Tool | Model Name | Role in Project | Runtime Calls During Audit |
| :--- | :--- | :--- | :--- |
| **Antigravity** | `gemini-3.8-flash` | Schema reverse-engineering & digest | 0 (Offline dev only) |
| **Argon** | `gemini-4-argon` | Architecture decomposition & roadmap | 0 (Offline dev only) |
| **GitHub Copilot** | `copilot-gpt-4o` | SQLite ingestion & BFS identity setup | 0 (Offline dev only) |
| **Codex** | `gpt-6-luna` | Operation typos patch & topological sort | 0 (Offline dev only) |
| **Gemini CLI** | `gemini-2.5-pro` | Ground-truth diagnostics & report packaging | 0 (Offline dev only) |

## 3. Production Runtime Resource & Cost Accounting (518 Cases)
| Metric | Full Fleet Run (518 Cases) | Grader Budget Limit |
| :--- | :--- | :--- |
| **Runtime LLM API Calls** | 0 calls | Unrestricted / Monitored |
| **Runtime Tokens Consumed** | 0 tokens | Budget Constrained |
| **Runtime Cost ($ USD)** | $0.00 | Budget Constrained |
| **Memory Footprint (RSS)** | ~35 MB | < 4 GB |
| **Local Cache Size** | ~25 MB (`northstar.db`) | < 1 GB |
