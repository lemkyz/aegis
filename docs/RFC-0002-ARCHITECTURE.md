# RFC-0002: Aegis System Architecture

- Status: Draft
- Version: 0.1
- Date: 2026-07-17
- Authors: Aegis Founding Team

## 1. Purpose

This RFC defines the initial system architecture of Aegis.

The architecture must support:

- VS Code integration
- Secure code generation
- Evidence-based vulnerability analysis
- Deterministic security tools
- Multiple AI models
- Specialist security agents
- Local project memory
- Controlled validation
- Future enterprise deployment

## 2. Architectural Principles

### 2.1 Local First

Repository reading, file indexing, scanner execution, and sensitive-context preparation should happen locally where possible.

### 2.2 Provider Independent

AI providers must be accessed through a common internal interface.

Aegis should be able to use NVIDIA-hosted models initially while supporting other providers later.

### 2.3 Evidence Before Conclusion

AI conclusions must be linked to scanner output, source locations, data flow, tests, or other inspectable evidence.

### 2.4 Structured Communication

Components must exchange structured JSON objects rather than unvalidated free-form text.

### 2.5 Human Approval

Code changes, security tests, and potentially consequential actions must require visible user approval.

### 2.6 Safe Execution

Generated code and validation tests must run inside isolated and explicitly authorized environments.

## 3. Initial Component Model

```text
┌─────────────────────────────────────────────┐
│               VS Code Extension             │
│                                             │
│  Commands · Chat · Findings · Diff Viewer   │
└──────────────────────┬──────────────────────┘
                       │ localhost HTTP
                       ▼
┌─────────────────────────────────────────────┐
│            Local Aegis Orchestrator         │
│                                             │
│ Request Router                              │
│ Context Builder                             │
│ Task Planner                                │
│ Policy Engine                               │
│ Result Aggregator                           │
└───────┬───────────────┬──────────────┬──────┘
        │               │              │
        ▼               ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ Security     │ │ Model        │ │ Knowledge    │
│ Engine       │ │ Gateway      │ │ Engine       │
│              │ │              │ │              │
│ Semgrep      │ │ GPT-OSS      │ │ OWASP        │
│ AST          │ │ Qwen         │ │ CWE          │
│ Secrets      │ │ Nemotron     │ │ Secure Rules │
│ Dependencies │ │ Future APIs  │ │ Project RAG  │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │                │
       └────────────────┼────────────────┘
                        ▼
               ┌─────────────────┐
               │ Finding Engine  │
               │                 │
               │ Evidence        │
               │ Confidence      │
               │ Severity        │
               │ Fix             │
               │ Tests           │
               └────────┬────────┘
                        ▼
               ┌─────────────────┐
               │ Project Memory  │
               │ SQLite initially│
               └─────────────────┘