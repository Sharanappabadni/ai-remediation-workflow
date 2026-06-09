# 🛡️ AI-Powered Package & Container Remediation Workflow

An automated remediation system that scans container images, npm packages, and Python packages for high/critical vulnerabilities and proposes safer alternatives using an LLM.

The workflow is orchestrated with **n8n**, implemented using **FastAPI + Trivy + LangChain**, and instrumented with **OpenTelemetry**. Traces are visualized in **Jaeger**.

---

## ✨ Features

- Supports container images, npm, and Python packages
- Detects direct and transitive vulnerabilities
- LLM suggests safer compatible versions
- Generates remediation artifacts and reports
- Distributed tracing with token and cost visibility
- Fully containerized and on-prem deployable

---

## 🏗 Architecture

User → n8n → FastAPI Agent → Trivy Scan → LLM  
                                              ↓  
                                     OpenTelemetry  
                                              ↓  
                                           Jaeger  

---

## 📁 Project Structure

```
.
├── agent/                 # FastAPI + Trivy + LangChain
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
├── n8n/                   # n8n workflow
├── shared/                # Generated reports & artifacts
├── otel-config.yaml
├── docker-compose.yml
├── .env
└── README.md
```

---

## 🚀 Setup

### 1. Create `.env`

```
OPENAI_API_KEY=sk-...
```

### 2. Start the stack

```
docker compose up -d --build
```

### 3. Access Services

- n8n: http://localhost:5678  
- Agent: http://localhost:8000  
- Jaeger: http://localhost:16687  

---

## 🔌 API

### POST `/analyze`

Example request:

```
{
  "input": "ubuntu:22.04"
}
```

---

## 📥 Supported Inputs

### 🐳 Container Images

Examples:

```
ubuntu:22.04
alpine:3.19
debian:11
```

Scanned using:

```
trivy image --image-src remote <image>
```

Outputs:

- shared/Dockerfile.remediated  
- shared/rebuild.sh  
- shared/report.md  

---

### 📦 npm Packages

Example:

```
lodash@4.17.21
```

Scanned via filesystem.  
Safer version written to:

```
shared/updated_package.txt
```

---

### 🐍 Python Packages

Example:

```
django==4.2.11
```

Uses:

- virtualenv
- pipdeptree (dependency graph)
- trivy fs scan

Safer version written to:

```
shared/updated_package.txt
```

---

## 📄 Output Report

Each run generates:

**shared/report.md** including:

- High/Critical count (before)
- High/Critical count (after)
- Removed CVEs
- Reduction percentage

---

## 🔭 Observability

Each request creates a trace named:

```
remediation_workflow
```

Captured attributes:

- before_vulns
- after_vulns
- reduction_percent
- execution_time
- llm_tokens
- llm_cost_estimate

View traces at:

```
http://localhost:16687
```

Service name: `ai-remediation-agent`

---

## 📈 Scaling (High-Level)

- Add Redis/RabbitMQ queue
- Run multiple FastAPI replicas
- Centralize OTEL collector
- Optional Prometheus + Grafana metrics

---

## 🧠 Design Approach

This project demonstrates:

- Deterministic scanning (Trivy)
- LLM-assisted remediation decisions
- Transparent observability
- Artifact-based output
- Fully containerized deployment

---
