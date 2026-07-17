# RFC-0001: Aegis Product Vision

- Status: Draft
- Version: 0.1
- Date: 2026-07-17
- Authors: Aegis Founding Team

## 1. Summary

Aegis is an AI-native security engineering platform that helps developers design, write, review, test, and maintain secure software from the first line of code.

Aegis combines AI coding assistance, deterministic security tools, evidence-based vulnerability analysis, authorized attack simulation, secure code generation, and continuous project memory in one development environment.

Aegis is not merely a chatbot, vulnerability scanner, or general-purpose coding assistant.

Aegis is an AI Security Engineer.

## 2. Problem

Modern software teams are under pressure to release code rapidly.

AI coding assistants increase development speed, but they may also generate insecure, outdated, or incorrectly configured code. Traditional security tools usually detect problems after code has already been written and often produce large numbers of false positives without explaining the real attack path.

Developers currently need to move between multiple disconnected tools:

- AI coding assistants
- Static analyzers
- Dependency scanners
- Secret scanners
- Container scanners
- Cloud security tools
- Vulnerability databases
- Penetration-testing tools
- Security documentation

These tools rarely share context, rarely explain findings clearly, and rarely help the developer safely fix and verify the issue inside the same workflow.

## 3. Vision

Aegis will become the security engineering layer inside modern software development.

A developer should be able to ask Aegis to create a feature, and Aegis should:

1. Understand the repository and its architecture.
2. Generate or modify the code.
3. Analyze the proposed change for security weaknesses.
4. Validate findings using deterministic security tools.
5. Simulate realistic attacks only inside authorized and controlled environments.
6. Produce evidence for every important finding.
7. Generate a secure fix.
8. Create security and regression tests.
9. Re-evaluate the fixed implementation.
10. Explain the final decision to the developer.

Aegis should not simply say:

> This code may be vulnerable.

It should say:

> User-controlled input reaches a dynamically constructed SQL query on line 53. Semgrep rule X detected the pattern, taint analysis confirmed the source-to-sink path, and three security models agreed that the issue is exploitable. The finding maps to CWE-89. Here is the secure patch and its regression test.

## 4. Product Positioning

Cursor helps developers write code faster.

Aegis helps developers write secure code faster and demonstrates why the result should be trusted.

Aegis will initially be delivered as a VS Code extension supported by a local or cloud-based security orchestration service.

Long-term, Aegis may become a complete AI-native secure development environment and enterprise application security platform.

## 5. Core Principles

### 5.1 Evidence First

Every important security finding should include verifiable evidence.

Evidence may include:

- File and line location
- Relevant code path
- Source-to-sink data flow
- Static-analysis result
- Dependency or CVE match
- Configuration evidence
- Reproducible test result
- Controlled proof of concept
- Model consensus
- Confidence score

### 5.2 AI Is Not the Source of Truth

Large language models may reason about findings, explain risk, generate fixes, and coordinate tools.

They must not be treated as the sole security authority.

Security decisions should combine:

- Deterministic analysis
- Runtime evidence
- Structured security knowledge
- Multiple model opinions where valuable
- Explicit uncertainty

### 5.3 Secure by Construction

Aegis should not only find vulnerabilities after development.

It should help prevent them while architecture and code are being created.

### 5.4 Authorized Environments Only

Attack simulation, exploit validation, fuzzing, and offensive testing must run only against systems, repositories, labs, or environments for which the user has explicit authorization.

The product must favor safe defaults, isolated execution, auditability, and clear scope controls.

### 5.5 Human Control

Aegis may recommend and prepare changes, but consequential actions should remain inspectable and controllable by the user.

Automatic changes must produce diffs, explanations, and rollback paths.

### 5.6 Model Independence

Aegis should not depend permanently on a single AI provider.

The platform should support multiple models and allow routing according to task, price, latency, privacy, and quality.

### 5.7 Privacy by Design

Source code and security findings may be highly sensitive.

Aegis must support:

- Minimal data collection
- Secret redaction
- Local analysis where possible
- Clear data-retention policies
- Provider isolation
- Enterprise-controlled storage
- Self-hosted deployment in later versions

## 6. Initial Target Users

The first users will be:

- Individual developers
- Security-conscious startup teams
- Application security engineers
- Ethical hackers working in authorized environments
- DevSecOps engineers
- Open-source maintainers

Later enterprise users may include:

- Fintech companies
- Banks
- Defense-industry software teams
- Healthcare technology companies
- Cloud infrastructure teams
- Large software organizations

## 7. MVP

The first MVP will be intentionally narrow.

A user selects code inside VS Code and runs:

> Aegis: Analyze Selected Code

Aegis returns:

- Finding title
- Severity
- Confidence
- Vulnerable file and lines
- Explanation
- CWE mapping
- OWASP mapping where applicable
- Evidence
- Secure fix
- Proposed code diff
- Security test
- False-positive considerations

The MVP will initially support Python code.

The first analysis pipeline will combine:

1. Selected source code
2. Repository context
3. One deterministic scanner
4. One primary AI model
5. Structured JSON output
6. A VS Code results panel

## 8. Product Differentiators

Aegis aims to differentiate through:

### 8.1 Evidence-Based Findings

Security results should be supported by code paths and tool output rather than unsupported AI claims.

### 8.2 Self-Adversarial Review

Code generated by Aegis should be reviewed from both attacker and defender perspectives before being presented as secure.

### 8.3 Multi-Model Consensus

For high-risk findings, multiple specialist models may independently evaluate the evidence.

A judge component will compare their conclusions and report disagreement rather than hiding it.

### 8.4 Security Memory

Aegis should remember the repository’s architecture, accepted risks, resolved findings, security rules, and recurring weaknesses.

### 8.5 Secure Coding Assistant

Aegis should eventually generate complete features while enforcing security requirements during implementation.

### 8.6 Controlled Attack Validation

When legally authorized and technically isolated, Aegis may generate and execute safe validation tests to determine whether a suspected issue is genuinely exploitable.

## 9. Non-Goals for the MVP

The MVP will not:

- Replace professional penetration testers
- Autonomously attack public systems
- Train a new foundation model from scratch
- Support every programming language
- Scan entire enterprise infrastructures
- Automatically merge code without review
- Claim that AI-generated findings are guaranteed correct
- Build a complete IDE from zero

## 10. Long-Term Capabilities

Potential future capabilities include:

- Repository-wide autonomous analysis
- Secure feature generation
- Pull-request security review
- Red-team and blue-team agents
- Model consensus and debate
- CodeQL integration
- Semgrep integration
- Tree-sitter and data-flow analysis
- Dependency and supply-chain security
- Secret detection
- Docker and Kubernetes analysis
- Terraform and cloud configuration analysis
- Malware triage
- Binary and reverse-engineering assistance
- Fuzz-test generation
- Threat modeling
- Attack-path visualization
- Enterprise policy enforcement
- Historical security memory
- On-premise and air-gapped deployment

## 11. Success Criteria for the First MVP

The MVP is successful when:

1. A developer can install the VS Code extension.
2. The developer can select Python code and request a security analysis.
3. Aegis returns structured results inside the editor.
4. At least five common vulnerability classes can be demonstrated.
5. Findings contain evidence and secure fixes.
6. The system can distinguish at least some false positives.
7. The proposed fix can be applied as a visible diff.
8. The fixed code can be re-analyzed.
9. The entire demonstration works reliably on a prepared test repository.
10. At least ten real developers test it and provide feedback.

## 12. Initial Vulnerability Scope

The first version should focus on a small number of high-value Python and web-security issues:

- SQL injection
- Command injection
- Path traversal
- Hardcoded secrets
- Insecure deserialization
- Server-side request forgery
- Cross-site scripting where relevant
- Weak authentication or session configuration
- Unsafe subprocess use
- Missing security controls in Flask applications

## 13. Technical Direction

The likely initial architecture consists of:

- VS Code extension written in TypeScript
- Local orchestration service written in Python
- NVIDIA-hosted models through an OpenAI-compatible API
- Semgrep as the first deterministic scanner
- Pydantic models for structured findings
- SQLite for local project memory
- JSON-based contracts between components
- Isolated test execution for later validation features

This direction is provisional and will be finalized in RFC-0002.

## 14. Business Direction

The first version may be free for individual developers.

Potential future business models include:

- Pro developer subscription
- Team subscription
- Enterprise licensing
- Self-hosted deployment
- Security policy and compliance modules
- Repository-scale continuous analysis
- Private model and data integrations

The product should prove developer value before optimizing for fundraising.

## 15. Founding Thesis

Software is increasingly written by AI, but security review has not evolved at the same speed.

The winning security platform will not merely scan AI-generated code after the fact.

It will participate in creating the software, challenge its own work, gather evidence, repair weaknesses, and continuously learn the security context of the project.

Aegis exists to become that platform.