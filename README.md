CARL — Compliance Assurance & Registry Ledger
CARL is a production-style FastAPI backend designed to simulate enterprise-grade compliance pipelines. It provides secure artifact ingestion, automated integrity verification, full audit logging, and an append-only, immutable ledger to track software lifecycles and guarantee data integrity.

> Why This Project Exists
In modern enterprise environments, deploying software blindly is a massive liability. Security and compliance teams need definitive proof that production code hasn't been tampered with. CARL addresses this challenge by implementing an end-to-end simulation of a zero-trust artifact pipeline, relying on four core pillars:

Tamper-Proof Verification: Cryptographic checking of all incoming files.

Absolute Auditability: A permanent record of every system action and state change.

Granular Access Control: Role-Based Access Control (RBAC) protecting sensitive operations.

Immutable Tracking: A blockchain-inspired, append-only ledger for finalized assets.

> Core System Capabilities
Secure Authentication: User management powered by OAuth2 and JWT tokens.

Role-Based Permissions: Distinct access tiers for Administrators, Auditors, Application Owners, and Viewers.

Application Registry: Centralized management of authorized software applications.

Artifact Pipeline: Secure file uploading coupled with automatic server-side SHA-256 generation.

Integrity Verification Engine: Cross-references user-provided hashes against actual server-computed hashes.

Simulated Immutable Ledger: Transparent, tamper-evident recording of successfully verified artifacts.

Comprehensive Logging: Deep audit trails capturing every critical event.

Compliance Dashboard: Live operational metrics, success/failure rates, and reporting endpoints.

Advanced Search: Multi-parameter filtering across the registry, audit logs, and ledger.

> System Architecture
CARL's design isolates the web layer, business logic, storage, and ledger components to ensure high maintainability and security.

Plaintext
Client (Swagger / Postman)
        │
        ▼
 FastAPI Backend
        │
        ├──► Authentication Layer (JWT + RBAC)
        ├──► Application Registry (SQLModel + SQLite)
        │
        ├──► Artifact Pipeline
        │     ├── File Upload (secure_vault/)
        │     ├── SHA-256 Hashing Engine
        │     └── Verification Engine
        │
        ├──► Immutable Ledger Layer
        │     └── Append-only Transaction Log
        │
        └──► Audit Logging System
> Authentication & Access Control
The Login Flow
Authenticate: Send a POST request to /api/login with your credentials.

Receive Token: The system returns a secure JWT bearer token.

Authorize: Attach the token to the header of subsequent requests: Authorization: Bearer <JWT_TOKEN>.

Role-Based Access Tiers
The system strictly enforces permissions based on user roles:

ADMINISTRATOR: Full system control. Granted ultimate authority to upload, verify, publish to the ledger, and alter system configurations.

AUDITOR: Granted read-only access to system states alongside exclusive access to audit logs, compliance summaries, and reports.

APPLICATION_OWNER: Responsible for managing application profiles and uploading new build artifacts for verification.

VIEWER: Restricted to read-only access for the general application registry and high-level dashboard metrics.

> End-to-End Workflow
Create an Application: Register a new software project profile via POST /api/applications.

Upload an Artifact: Push a build package using POST /api/artifacts/upload. The request takes a multipart file upload alongside a precomputed SHA-256 hash and metadata.

Verify Integrity: Trigger POST /api/verify/{artifact_id}. The system hashes the file on the server and matches it against your precomputed hash. If they match, the status updates to Verified; otherwise, it flags a Hash Mismatch.

Publish to the Ledger: Commit verified artifacts permanently using POST /api/blockchain/publish/{artifact_id}. This writes an unalterable transaction entry to the ledger.

Example Artifact Upload Command
Bash
curl -X POST "http://127.0.0.1:8000/api/artifacts/upload" \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -F "application_id=1" \
  -F "artifact_type=DOCUMENT" \
  -F "version=v1.0" \
  -F "description=Production release package" \
  -F "submitted_hash=abc123xyz..." \
  -F "file=@release.zip"
>API Endpoint Reference
Authentication
POST /api/login — Exchange credentials for a JWT token.

Application Management
POST /api/applications — Register a new application.

GET /api/applications — List all registered applications.

GET /api/applications/{id} — Retrieve specific application metadata.

GET /api/applications/{id}/artifacts — View all artifacts tied to a specific app.

Artifact Management
POST /api/artifacts/upload — Securely upload a file package with a metadata payload.

GET /api/artifacts — List all managed artifacts.

GET /api/artifacts/{id} — Fetch detailed artifact status.

Compliance & Verification
POST /api/verify/{artifact_id} — Run the cryptographic verification engine.

POST /api/verify/{artifact_id}/simulate-failure — Force an integrity failure state for testing/demo purposes.

Ledger & Auditing
POST /api/blockchain/publish/{artifact_id} — Commit a verified artifact to the append-only ledger.

GET /api/blockchain — View the historical ledger timeline.

GET /api/audit — Query the global system audit trails.

Dashboards & Reporting
GET /api/search — Unified, multi-field search across system records.

GET /api/dashboard — High-level metric aggregation.

GET /api/compliance-summary — Status overview of compliance KPIs.

GET /api/reports/daily | monthly | failures | audit — Specialized data rollups for governance reviews.

> Core Security & Ledger Design
Defensive Architecture
Cryptographic Passwords: User credentials are securely salted and hashed using bcrypt via Passlib.

Token Expirations: Issued JWT access tokens automatically expire after 8 hours to minimize exposure windows.

Isolated Storage: Uploaded files live in a dedicated secure_vault/ directory with direct execution disabled to mitigate remote code execution (RCE) risks.

Simulated Ledger Mechanics
Rather than adding the overhead of a full blockchain network, CARL implements a localized append-only ledger design. Every committed transaction includes the artifact’s unique SHA-256 hash, an unalterable server timestamp, and a sequential cryptographic signature. This guarantees tamper evidence and historical non-repudiation.

>Tech Stack & Structure
Framework: FastAPI (Python 3.10+)

Database & ORM: SQLModel backed by SQLite

Security & Crypto: Python-jose (JWT processing) & Passlib (Bcrypt)

Server ASGI: Uvicorn

Project Layout
Plaintext
├── main.py                # Core backend engine, routers, and business logic
├── secure_vault/          # Secure local repository for ingested artifacts
└── compliance_final.db    # Local relational database
> Quickstart & Local Setup
Install Dependencies:

Bash
pip install -r requirements.txt
Launch the Server:

Bash
uvicorn main:app --reload
Explore the System:
Open your browser and navigate to http://127.0.0.1:8000/docs to view and interact with the live, auto-generated Swagger UI.
