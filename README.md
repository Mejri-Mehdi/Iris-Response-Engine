# IRIS — Incident Response Playbook Automation Engine

<div align="center">

![IRIS](https://img.shields.io/badge/IRIS-SOAR-blue?style=for-the-badge&logo=shield)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-green.svg?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0%2B-red.svg?style=flat-square&logo=sqlalchemy&logoColor=white)](https://www.sqlalchemy.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

**A lightweight, extensible SOAR-like incident response automation engine designed for SecOps and SOC engineering.**

[Features](#-features) • [Architecture](#-architecture) • [Tech Stack](#-tech-stack) • [Quickstart](#-getting-started) • [API Docs](#-api-endpoints) • [Playbooks](#-playbooks)

</div>

---

## 📌 Overview

**IRIS** is an automated Incident Response (SOAR) engine that ingests security incident tickets (JSON), executes step-by-step security playbooks, enriches IOCs with mock threat intelligence, simulates containment actions, and compiles a comprehensive audit timeline and evidence package.

Built with modern Python, FastAPI, SQLAlchemy 2.0, and Pydantic v2, this project provides a production-style foundation for **security automation**, **backend engineering**, and **incident response orchestration**.

---

## ✨ Features

- 📜 **Playbook-Driven Automation**: Define response logic in declarative YAML with conditional branching and templating.
- 🛡️ **Standardized Incident Schema**: Strongly typed Pydantic models for incident payloads, observables, and artifacts.
- 🔍 **Threat Intel Enrichment (Mocked)**: Automated lookups for VirusTotal hashes, IP reputation, malicious URLs, and GeoIP.
- ⚡ **Containment Simulation**: Host isolation, account suspension, IP blocking, process termination, VM snapshotting, and file quarantine.
- 🗄️ **Evidence & Artifact Collection**: Persistent record linking raw logs, network captures, and containment output to incidents.
- ⏱️ **Timeline Reconstruction**: Interactive chronological view rendered in JSON, ASCII (CLI), or formatted HTML.
- 🚀 **Asynchronous REST API**: FastAPI backend with non-blocking background tasks and OpenAPI documentation.
- 💻 **Interactive CLI**: Operator-focused terminal tool for incident creation, live tracking, and report generation.
- 💾 **Relational Persistence**: SQLite storage powered by SQLAlchemy 2.0 ORM.
- 🧪 **Comprehensive Test Suite**: Unit and integration tests with coverage reporting.

---

## 🏗 Architecture

```text
┌─────────────┐       ┌──────────────┐       ┌─────────────────┐
│  CLI Tool   │──────▶│ FastAPI API  │──────▶│ SQLite Database │
│  (cli.py)   │       │ (api/main.py)│       │    (iris.db)    │
└─────────────┘       └──────┬───────┘       └─────────────────┘
                             │
                             ▼
                    ┌────────────────┐
                    │ IncidentTriage │ (Orchestrator)
                    └───────┬────────┘
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
┌──────────────┐     ┌─────────────┐     ┌─────────────────┐
│   Playbook   │     │  Enricher   │     │   Containment   │
│    Engine    │     │ (Mock Intel)│     │    Simulator    │
└──────────────┘     └─────────────┘     └─────────────────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ▼
                    ┌────────────────┐
                    │  Timeline &    │
                    │    Evidence    │
                    └────────────────┘
```

### Execution Flow
1. **Ingest**: Incident arrives via REST API or CLI.
2. **Triage**: The `IncidentTriage` orchestrator resolves incident severity/type and loads the corresponding playbook.
3. **Execution**: Playbook steps are dispatched to target handlers (`enricher`, `containment`, etc.).
4. **Context & Evidence**: Step results update the shared incident context, generate evidence artifacts, and record timeline events.
5. **Reporting**: Timeline and artifacts are finalized in the database and made available via API endpoints and CLI views.

---

## 🛠 Tech Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Language** | Python 3.10+ | Core runtime |
| **API Framework** | FastAPI | REST API & Async background tasks |
| **Data Validation** | Pydantic v2 | Strict schema validation & serialization |
| **ORM / Database** | SQLAlchemy 2.0 / SQLite | Relational persistence & audit trail |
| **Playbook Engine** | PyYAML + Jinja2 | Dynamic step definitions & templating |
| **CLI Framework** | argparse | Command-line interface for operators |
| **Testing** | pytest, pytest-cov | Unit, integration tests & code coverage |
| **HTTP Client** | httpx (TestClient) | API testing |

---

## 📁 Project Structure

```text
iris-response-engine/
├── api/
│   ├── __init__.py
│   └── main.py              # FastAPI application & route handlers
├── playbooks/               # Declarative YAML response playbooks
│   ├── malware_outbreak.yml
│   ├── phishing_campaign.yml
│   ├── data_exfiltration.yml
│   └── insider_threat.yml
├── src/
│   ├── __init__.py
│   ├── models.py            # SQLAlchemy models & database initialization
│   ├── schemas.py           # Pydantic schemas (requests, responses, observables)
│   ├── playbook_engine.py   # YAML loader, parser, and state execution engine
│   ├── enricher.py          # Threat intel enrichment handlers & cache
│   ├── containment.py       # Simulated containment actions & sandbox effects
│   ├── timeline.py          # Timeline aggregation & formatters (JSON/HTML/ASCII)
│   └── triage.py            # Main incident triage orchestrator
├── templates/
│   └── timeline.html        # Jinja2 template for HTML timeline rendering
├── tests/                   # Pytest automated test suite
├── cli.py                   # Command-line operator interface
├── requirements.txt         # Project dependencies
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+**
- **pip** and **git**

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/iris-response-engine.git
   cd iris-response-engine
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate

   # Windows
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database:** *(optional – automatically runs on API startup)*
   ```bash
   python -c "from src.models import init_db, get_engine; init_db(get_engine())"
   ```

---

## 📌 Usage

### Running the FastAPI Backend

Start the development server with hot-reload:

```bash
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

- **API Base URL**: `http://127.0.0.1:8000`
- **Interactive Swagger UI**: `http://127.0.0.1:8000/docs`
- **Alternative ReDoc UI**: `http://127.0.0.1:8000/redoc`
- **Health Check**: `http://127.0.0.1:8000/health`

---

### Using the CLI Tool

The CLI operates standalone or alongside the API:

```bash
python cli.py --help
```

#### Common Commands

- **Create an Incident:**
  ```bash
  python cli.py create-incident \
    --type malware \
    --host WS-1234 \
    --severity critical \
    --description "Ransomware detected on workstation" \
    --source-ip 185.20.30.40
  ```

- **Watch Live Playbook Execution:**
  ```bash
  python cli.py watch --incident-id INC-2026-0001
  ```

- **List Incidents:**
  ```bash
  python cli.py list --status open --limit 20
  ```

- **Show Incident Details:**
  ```bash
  python cli.py show --incident-id INC-2026-0001
  ```

- **Generate Report (Text / JSON):**
  ```bash
  python cli.py report --incident-id INC-2026-0001 --format text
  ```

- **Render ASCII Timeline in Terminal:**
  ```bash
  python cli.py timeline --incident-id INC-2026-0001 --format ascii
  ```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/incidents` | Ingest incident and trigger playbook asynchronously (202 Accepted) |
| `GET` | `/incidents` | List incidents (filter by `status`, `severity`, or `type`) |
| `GET` | `/incidents/{id}` | Fetch incident details, execution status, and evidence artifacts |
| `GET` | `/incidents/{id}/timeline` | Retrieve timeline (`format=json`, `format=html`, `format=ascii`) |
| `GET` | `/incidents/{id}/report` | Generate comprehensive incident post-mortem report |
| `POST` | `/incidents/{id}/retry` | Retry a failed playbook execution step |
| `GET` | `/playbooks` | List all available YAML response playbooks |
| `GET` | `/health` | Application status, version, and database connectivity |

---

## 📜 Playbooks

IRIS comes pre-configured with four built-in security playbooks:

| Playbook ID | Description | Default Severity Triggers |
| :--- | :--- | :--- |
| `malware_outbreak` | Standard host containment, hash reputation check, process kill, and VM snapshot | `critical`, `high` |
| `phishing_campaign` | URL reputation scan, credential reset, inbox sweep, and firewall domain block | `high`, `medium` |
| `data_exfiltration` | Egress IP block, DLP artifact capture, user token revocation, and forensic dump | `critical` |
| `insider_threat` | User privilege suspension, session termination, audit log extraction | `high`, `critical` |

> Playbooks are defined under `playbooks/*.yml` and can be customized or expanded without modifying application code.

---

## 🧪 Testing

Execute the test suite with coverage reporting:

```bash
pytest tests/ -v --cov=src --cov=api --cov-report=term-missing
```

### Coverage Summary

| Module | Statements Covered |
| :--- | :--- |
| `src/schemas.py` | 100% |
| `src/models.py` | 95% |
| `src/enricher.py` | 78% |
| `src/containment.py` | 73% |
| `src/triage.py` | 73% |
| `api/main.py` | 65% |

---

## 📸 Screenshots

---
![alt text](</docs/screenshots/Screenshot 2026-08-23 190414.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-08-23 190421.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-08-23 191008.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-08-23 191412.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-08-23 191416.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-08-23 191428.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-08-23 191449.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-08-23 191636.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-08-23 192942.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-08-23 192017.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-08-23 192143.png>)
---
![alt text](</docs/screenshots/Screenshot 2026-08-23 192345.png>)
---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/NewPlaybook`)
3. Commit your Changes (`git commit -m 'feat: Add cloud lateral movement playbook'`)
4. Push to the Branch (`git push origin feature/NewPlaybook`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

## 👤 Author

**Mehdi Mejri**  
- GitHub: [@Mejri-Mehdi](https://github.com/Mejri-Mehdi)  
- LinkedIn: [in/mehdi-mejri](https://www.linkedin.com/in/mehdi-mejri)  

*Built with passion for security automation and incident response.*