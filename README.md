# Spectral ⚡

> **High-Performance Secret Scanner & API Key Hunter in Go**

[![Spectral CI](https://github.com/ispectr3/spectral/actions/workflows/ci.yml/badge.svg)](https://github.com/ispectr3/spectral/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-orange?style=flat-square)](https://docs.github.com/en/code-security/code-scanning)

**Spectral** is a blazing-fast, concurrent secret scanner engineered in Go for offensive security researchers, bug bounty hunters, and DevSecOps teams. It identifies leaked API keys and tokens across filesystems, `.env` files, and Git commit histories with near-zero false positives.

Inspired by modern threat hunting workflows, Spectral pairs **unique segment pattern matching** with **Shannon entropy thresholding** and an **optional live verification engine** to confirm active credentials in milliseconds.

---

## Architecture & Detection Pipeline

```mermaid
flowchart TD
    subgraph Ingestion ["1. Multi-Source Ingestion"]
        A[Local Filesystem Walk]
        B[Git Commit History Diff]
        C[Standard Input Stream / Stdin]
    end

    subgraph Pipeline ["2. Concurrent Scanning Engine"]
        D[Worker Pool (Default: 16 Goroutines)]
        E[Binary File Heuristics: Null Byte Rejection]
        F[Aho-Corasick & Fast Substring Pre-Filter]
    end

    subgraph Evaluation ["3. Verification & Entropy Defense"]
        G[Exact Provider Regex Match]
        H[Shannon Entropy H > 3.0 Threshold]
        I[Placeholder Elimination: 'your_key', 'test_xxx']
        J{Verify Flag Enabled?}
        K[Live API Probe: Non-destructive Liveness Check]
    end

    subgraph Output ["4. Exporters & CI/CD"]
        L[Color-Coded Terminal Table]
        M[Machine-Readable JSON]
        N[SARIF 2.1.0 GitHub Security]
    end

    A --> D
    B --> D
    C --> D
    D --> E --> F --> G --> H --> I --> J
    J -- Yes --> K --> L
    J -- No --> L
    K --> M
    K --> N
    L --> M
    L --> N
```

---

## Core Capabilities

- **🚀 Blazing Fast Concurrency:** Multi-threaded worker pool powered by native Go goroutines, processing thousands of files per second.
- **🎯 Unique Segment Detection:** Eliminates false alarms from documentation/tutorials by requiring immutable byte segments (e.g., `T3BlbkFJ` in modern OpenAI keys, `sk-ant-api03-` in Anthropic).
- **🔬 Shannon Entropy Filtering:** Calculates information entropy $H(X) = -\sum P(x_i) \log_2 P(x_i)$ to discard repetitive placeholders and non-random test values.
- **📜 Git Commit History Walker:** Scans full commit diffs (`git log -p`) to catch secrets that were committed and subsequently deleted in later revisions.
- **⚡ Live Verification Engine:** Non-destructive, non-metered HTTP probes verifying whether discovered tokens are **ACTIVE**, **REVOKED**, or **RATE LIMITED** across OpenAI, Anthropic, Stripe, GitHub, and HuggingFace.
- **🛡️ SARIF 2.1.0 Ready:** Native exporter formatted for automated integration into GitHub Code Scanning and Security tabs.
- **📦 Zero External Runtime Dependencies:** Pure Go standard library architecture, compiling to a self-contained static binary.

---

## Supported Providers & Detection Accuracy

| Provider | Signature / Pattern Mechanism | Target Environment | Live Verification |
| :--- | :--- | :--- | :---: |
| **OpenAI (Project)** | `sk-proj-[A-Za-z0-9_-]{8,}T3BlbkFJ...` | AI & LLM Applications | ✅ |
| **OpenAI (Legacy)** | `sk-[A-Za-z0-9]{48}` | AI & LLM Applications | ✅ |
| **Anthropic** | `sk-ant-api03-[A-Za-z0-9_-]{80,110}` | Claude LLM Endpoints | ✅ |
| **AWS IAM** | `(AKIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{16}` | Cloud Infrastructure | ✅ |
| **Stripe** | `sk_live_[0-9a-zA-Z]{24,99}` | Payment Gateways | ✅ |
| **GitHub** | `ghp_[0-9a-zA-Z]{36}`, `github_pat_...` | Source Code & CI/CD | ✅ |
| **HuggingFace** | `hf_[0-9a-zA-Z]{34}` | ML Model Repositories | ✅ |
| **Google Gemini** | `AIzaSy[A-Za-z0-9_-]{33}` | Cloud & AI Services | ✅ |
| **Slack** | `xoxb-[0-9]{10,13}-[0-9]{10,13}-...` | Chat & Bot Automations | ✅ |
| **Groq Cloud** | `gsk_[a-zA-Z0-9]{52}` | AI Inference Platforms | — |
| **Pinecone** | `pcsk_[a-zA-Z0-9_-]{48,70}` | Vector Databases | — |
| **SendGrid** | `SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}` | Email Infrastructure | — |
| **Resend** | `re_[a-zA-Z0-9]{32,48}` | Developer Email APIs | — |
| **Discord** | `[MN][A-Za-z0-9]{23,25}\...` | Bot Authorizations | — |
| **Telegram** | `[0-9]{9,10}:[a-zA-Z0-9_-]{35}` | Bot Integrations | — |
| **Postman** | `PMAK-[a-f0-9]{24}-[a-f0-9]{34}` | Workspace Integrations | — |

---

## Installation

### From Source
```bash
git clone https://github.com/ispectr3/spectral.git
cd spectral
go build -o spectral ./cmd/spectral
```

### Via `go install`
```bash
go install github.com/ispectr3/spectral/cmd/spectral@latest
```

---

## Quick Start & Usage

### 1. Scan Local Directory / Repository
```bash
# Scan current directory with 16 threads
./spectral -path .

# Scan specific directory with 32 concurrent workers
./spectral -path /path/to/project -threads 32
```

### 2. Verify Active Secrets (Liveness Probing)
```bash
# Audit and verify whether detected tokens are live against provider APIs
./spectral -path . -verify

# Filter output to display ONLY active live credentials
./spectral -path . -verified-only
```

### 3. Scan Full Git Commit History
```bash
# Inspect every commit patch diff for previously committed credentials
./spectral -path /path/to/git/repo -git
```

### 4. Standard Input (Piped Input)
```bash
cat .env | ./spectral
docker logs container_name | ./spectral
```

### 5. CI/CD & SARIF Integration
```bash
# Generate SARIF 2.1.0 for GitHub Code Scanning
./spectral -path . -sarif results.sarif

# Export JSON report
./spectral -path . -json -output findings.json
```

---

## GitHub Actions CI Integration Example

Add Spectral to your `.github/workflows/security.yml`:

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Full history for git scanning

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install Spectral
        run: go install github.com/ispectr3/spectral/cmd/spectral@latest

      - name: Run Secret Scan & Generate SARIF
        run: spectral -path . -git -sarif spectral-results.sarif

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: spectral-results.sarif
```

---

## License

Distributed under the MIT License. See `LICENSE` for details.
