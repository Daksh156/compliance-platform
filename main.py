from enum import Enum
from typing import Optional, List
from datetime import datetime, timezone, timedelta
import os
import hashlib
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, HTTPException, status, Query, Form, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlmodel import SQLModel, Field, create_engine, Session, select, func
from jose import JWTError, jwt
from passlib.context import CryptContext

# ==========================================
# 1. INITIALIZATION & DATABASE CONNECTIONS
# ==========================================

sqlite_file_name = "compliance_final.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles application startup events.
    Creates tables and pre-seeds default users with hashed passwords
    before the server begins accepting requests.
    """
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        if session.exec(select(func.count(User.id))).one() == 0:
            # FIX 1: Users now have hashed passwords. Default credentials shown below.
            # admin_daksh   / Admin@123
            # sec_auditor   / Audit@123
            # app_dev_lead  / Dev@123
            # viewer_one    / View@123
            session.add(User(username="admin_daksh",  password_hash=pwd_context.hash("Admin@123"), role=UserRole.ADMINISTRATOR))
            session.add(User(username="sec_auditor",  password_hash=pwd_context.hash("Audit@123"), role=UserRole.AUDITOR))
            session.add(User(username="app_dev_lead", password_hash=pwd_context.hash("Dev@123"),   role=UserRole.APPLICATION_OWNER))
            session.add(User(username="viewer_one",   password_hash=pwd_context.hash("View@123"),  role=UserRole.VIEWER))
            session.commit()
    yield


app = FastAPI(
    title="Compliance Assurance & Registry Ledger (CARL)",
    description="Enterprise Blueprint for Automated Ingestion & Cryptographic Integrity Verification",
    version="1.0.0",
    lifespan=lifespan
)

# ==========================================
# 2. ENUMS & SECURITY CONFIGURATIONS
# ==========================================

UPLOAD_FOLDER = "secure_vault"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = [".zip", ".tar", ".tar.gz", ".7z"]

SECRET_KEY = "daksh-compliance-secret-key-change-in-production"
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8  # FIX 2: Tokens expire after 8 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


class ArtifactType(str, Enum):
    DATABASE = "DATABASE"
    DOCUMENT = "DOCUMENT"
    CONFIGURATION = "CONFIGURATION"
    APPLICATION = "APPLICATION"


class UserRole(str, Enum):
    ADMINISTRATOR = "ADMINISTRATOR"
    AUDITOR = "AUDITOR"
    APPLICATION_OWNER = "APPLICATION_OWNER"
    VIEWER = "VIEWER"


# ==========================================
# 3. CORE DATA SCHEMAS (DATA ACCESS LAYER)
# ==========================================

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str
    password_hash: str   # FIX 1: Store hashed password, never plaintext
    role: UserRole


class LoginRequest(SQLModel):
    username: str
    password: str        # FIX 1: Require password on login


class TokenResponse(SQLModel):
    access_token: str
    token_type: str


class Application(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    owner: str
    department: str
    environment: str
    contact_email: str
    retention_policy: str


class ApplicationCreate(SQLModel):
    """Separate input schema so clients cannot inject an id on creation."""
    name: str
    owner: str
    department: str
    environment: str
    contact_email: str
    retention_policy: str


class Artifact(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    filename: str
    sha256_hash: str
    status: str              # Pending Verification | Verified | Hash Mismatch | Corrupted | Processing Failed
    application_id: int = Field(foreign_key="application.id")
    artifact_type: ArtifactType
    version: str
    description: str
    submission_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verification_time: Optional[datetime] = None


class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    action: str              # UPLOAD | VERIFY_SUCCESS | VERIFY_FAILED | BLOCKCHAIN_SUBMISSION | LOGIN | LOGOUT | CONFIG_CHANGE
    artifact_id: Optional[int] = None
    performed_by: Optional[str] = None   # FIX 4: Record which user triggered the action
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ComplianceRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    artifact_id: int
    application_id: int
    application_name: str
    artifact_name: str
    version: str
    submitted_hash: str
    calculated_hash: str
    verification_status: str  # Pending | Verified | Failed | Corrupted | Processing Failed
    submission_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verification_time: Optional[datetime] = None
    blockchain_transaction_id: Optional[str] = None
    submitter: str


class BlockchainRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    artifact_id: int
    artifact_hash: str
    transaction_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ==========================================
# 4. IDENTITY, ACCESS MANAGEMENT & RBAC
# ==========================================

def get_current_user(credentials=Depends(security)):
    """
    Decodes the Bearer JWT and returns the payload.
    Raises 401 if the token is invalid or expired.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token. Please log in again."
        )


def require_role(allowed_roles: list):
    """
    Role-Based Access Control factory.
    Returns a dependency that enforces the caller belongs to one of allowed_roles.
    """
    def role_checker(current_user=Depends(get_current_user)):
        user_role = current_user.get("role")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {allowed_roles}"
            )
        return current_user
    return role_checker


@app.post("/api/login", response_model=TokenResponse, tags=["Authentication"])
def login(data: LoginRequest):
    """
    Authenticates a user with username + password.
    Returns a signed JWT valid for 8 hours.

    Default test credentials:
    - admin_daksh  / Admin@123  (ADMINISTRATOR)
    - sec_auditor  / Audit@123  (AUDITOR)
    - app_dev_lead / Dev@123    (APPLICATION_OWNER)
    - viewer_one   / View@123   (VIEWER)
    """
    with Session(engine) as session:
        user = session.exec(
            select(User).where(User.username == data.username)
        ).first()

        # FIX 1: Verify both username exists AND password matches the stored hash
        if not user or not pwd_context.verify(data.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

        # FIX 2: Include expiry claim so tokens are not valid forever
        expiry = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
        token = jwt.encode(
            {
                "sub": user.username,
                "role": user.role,
                "exp": expiry          # Token expires after TOKEN_EXPIRE_HOURS
            },
            SECRET_KEY,
            algorithm=ALGORITHM
        )

        session.add(AuditLog(
            action=f"LOGIN",
            performed_by=user.username
        ))
        session.commit()

        return {"access_token": token, "token_type": "bearer"}


# ==========================================
# 5. CORE BUSINESS LOGIC & COMPLIANCE PIPELINE
# ==========================================

@app.post("/api/applications", response_model=Application, status_code=status.HTTP_201_CREATED, tags=["Applications"])
def register_application(
    app_data: ApplicationCreate,
    current_user=Depends(require_role(["ADMINISTRATOR", "APPLICATION_OWNER"]))
):
    """Registers a new application that will be submitting compliance packages."""
    with Session(engine) as session:
        new_app = Application(**app_data.model_dump())
        session.add(new_app)
        session.commit()
        session.refresh(new_app)

        session.add(AuditLog(
            action="CONFIG_CHANGE - APPLICATION_REGISTERED",
            performed_by=current_user.get("sub")
        ))
        session.commit()

        return new_app


@app.post("/api/artifacts/upload", response_model=Artifact, status_code=status.HTTP_201_CREATED, tags=["Artifacts"])
async def upload_artifact(
    application_id: int = Form(...),
    artifact_type: ArtifactType = Form(...),
    version: str = Form(...),
    description: str = Form(...),
    submitted_hash: str = Form(...),
    file: UploadFile = File(...),
    current_user=Depends(require_role(["ADMINISTRATOR", "APPLICATION_OWNER"]))
):
    """
    Accepts an archive file submission with its pre-computed SHA-256 hash.
    Saves the file, computes the hash server-side, and creates a compliance record.
    Verification is a separate step via POST /api/verify/{artifact_id}.
    """
    filename_lower = file.filename.lower()
    is_valid_ext = any(filename_lower.endswith(ext) for ext in ALLOWED_EXTENSIONS)
    if not is_valid_ext:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format. Accepted: {ALLOWED_EXTENSIONS}"
        )

    with Session(engine) as session:
        application = session.get(Application, application_id)
        if not application:
            raise HTTPException(status_code=404, detail="Application not found")

        file_content = await file.read()

        # FIX 3: Prepend a UUID to prevent filename collisions in secure_vault
        safe_original = os.path.basename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{safe_original}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)

        with open(file_path, "wb") as buffer:
            buffer.write(file_content)

        calculated_hash = hashlib.sha256(file_content).hexdigest()

        artifact = Artifact(
            filename=unique_filename,
            sha256_hash=calculated_hash,
            status="Pending Verification",
            application_id=application_id,
            artifact_type=artifact_type,
            version=version,
            description=description
        )
        session.add(artifact)
        session.flush()

        record = ComplianceRecord(
            artifact_id=artifact.id,
            application_id=application_id,
            application_name=application.name,
            artifact_name=safe_original,
            version=version,
            submitted_hash=submitted_hash,
            calculated_hash=calculated_hash,
            verification_status="Pending",
            submitter=current_user.get("sub", "unknown")
        )
        session.add(record)

        session.add(AuditLog(
            action="UPLOAD",
            artifact_id=artifact.id,
            performed_by=current_user.get("sub")
        ))
        session.commit()
        session.refresh(artifact)
        return artifact


@app.post("/api/verify/{artifact_id}", tags=["Verification"])
def verify_artifact(
    artifact_id: int,
    current_user=Depends(require_role(["ADMINISTRATOR", "AUDITOR"]))
):
    """
    Compares the submitted hash against the server-computed hash.
    Sets artifact status to Verified or Hash Mismatch accordingly.
    """
    with Session(engine) as session:
        artifact = session.get(Artifact, artifact_id)
        if not artifact:
            raise HTTPException(status_code=404, detail="Artifact not found")

        compliance_record = session.exec(
            select(ComplianceRecord).where(ComplianceRecord.artifact_id == artifact.id)
        ).first()
        if not compliance_record:
            raise HTTPException(status_code=404, detail="Compliance record not found")

        now = datetime.now(timezone.utc)

        if compliance_record.submitted_hash == compliance_record.calculated_hash:
            artifact.status = "Verified"
            action_status = "VERIFY_SUCCESS"
            compliance_record.verification_status = "Verified"
        else:
            artifact.status = "Hash Mismatch"
            action_status = "VERIFY_FAILED"
            compliance_record.verification_status = "Failed"

        artifact.verification_time = now
        compliance_record.verification_time = now

        session.add(artifact)
        session.add(compliance_record)
        session.add(AuditLog(
            action=action_status,
            artifact_id=artifact.id,
            performed_by=current_user.get("sub")
        ))
        session.commit()

        return {"result": artifact.status, "artifact_id": artifact.id}


@app.post("/api/blockchain/publish/{artifact_id}", tags=["Blockchain"])
def publish_to_blockchain(
    artifact_id: int,
    current_user=Depends(require_role(["ADMINISTRATOR"]))
):
    """
    Publishes the verified SHA-256 hash as a simulated immutable blockchain record.
    Only Verified artifacts can be published. Each artifact can only be published once.
    """
    with Session(engine) as session:
        artifact = session.get(Artifact, artifact_id)
        if not artifact:
            raise HTTPException(status_code=404, detail="Artifact not found")

        if artifact.status != "Verified":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Only Verified artifacts can be published. Current status: '{artifact.status}'"
            )

        compliance_record = session.exec(
            select(ComplianceRecord).where(ComplianceRecord.artifact_id == artifact.id)
        ).first()

        if compliance_record.blockchain_transaction_id:
            return {
                "message": "Already published",
                "blockchain_transaction_id": compliance_record.blockchain_transaction_id
            }

        tx_timestamp = datetime.now(timezone.utc)
        generated_tx_id = f"TXN-BLOCK-{artifact.id}-{uuid.uuid4().hex[:12].upper()}"

        blockchain_entry = BlockchainRecord(
            artifact_id=artifact.id,
            artifact_hash=artifact.sha256_hash,
            transaction_id=generated_tx_id,
            timestamp=tx_timestamp
        )
        session.add(blockchain_entry)

        compliance_record.blockchain_transaction_id = generated_tx_id
        session.add(compliance_record)

        session.add(AuditLog(
            action="BLOCKCHAIN_SUBMISSION",
            artifact_id=artifact.id,
            performed_by=current_user.get("sub")
        ))
        session.commit()

        return {
            "status": "Anchored to Immutable Ledger",
            "transaction_id": generated_tx_id,
            "artifact_hash": artifact.sha256_hash,
            "timestamp": tx_timestamp.isoformat()
        }


# ==========================================
# 6. BULK SEARCH & SECURE SYSTEM LOOKUPS
# ==========================================

@app.get("/api/applications", response_model=List[Application], tags=["Applications"])
def get_applications(current_user=Depends(get_current_user)):
    with Session(engine) as session:
        return session.exec(select(Application)).all()


@app.get("/api/applications/{application_id}", response_model=Application, tags=["Applications"])
def get_application(application_id: int, current_user=Depends(get_current_user)):
    with Session(engine) as session:
        app = session.get(Application, application_id)
        if not app:
            raise HTTPException(status_code=404, detail="Application not found")
        return app


@app.get("/api/applications/{application_id}/artifacts", response_model=List[Artifact], tags=["Applications"])
def get_application_artifacts(application_id: int, current_user=Depends(get_current_user)):
    with Session(engine) as session:
        if not session.get(Application, application_id):
            raise HTTPException(status_code=404, detail="Application not found")
        return session.exec(
            select(Artifact).where(Artifact.application_id == application_id)
        ).all()


@app.get("/api/artifacts", response_model=List[Artifact], tags=["Artifacts"])
def get_artifacts(current_user=Depends(get_current_user)):
    with Session(engine) as session:
        return session.exec(select(Artifact)).all()


@app.get("/api/artifacts/{artifact_id}", response_model=Artifact, tags=["Artifacts"])
def get_artifact(artifact_id: int, current_user=Depends(get_current_user)):
    with Session(engine) as session:
        artifact = session.get(Artifact, artifact_id)
        if not artifact:
            raise HTTPException(status_code=404, detail=f"Artifact {artifact_id} not found")
        return artifact


@app.get("/api/search", response_model=List[ComplianceRecord], tags=["Search"])
def advanced_compliance_search(
    application_name: Optional[str] = Query(None, description="Filter by application name (partial match)"),
    artifact_type: Optional[ArtifactType] = Query(None, description="Filter by artifact type"),
    version: Optional[str] = Query(None, description="Filter by version string"),
    sha256_hash: Optional[str] = Query(None, description="Filter by submitted or calculated hash"),
    blockchain_transaction_id: Optional[str] = Query(None, description="Filter by blockchain transaction ID"),
    from_date: Optional[datetime] = Query(None, description="Filter submissions from this date (ISO 8601)"),
    to_date: Optional[datetime] = Query(None, description="Filter submissions up to this date (ISO 8601)"),
    current_user=Depends(get_current_user)
):
    """Search compliance records by any combination of filters."""
    with Session(engine) as session:
        query = select(ComplianceRecord)

        if application_name:
            query = query.where(ComplianceRecord.application_name.contains(application_name))
        if version:
            query = query.where(ComplianceRecord.version == version)
        if sha256_hash:
            query = query.where(
                (ComplianceRecord.submitted_hash == sha256_hash) |
                (ComplianceRecord.calculated_hash == sha256_hash)
            )
        if blockchain_transaction_id:
            query = query.where(ComplianceRecord.blockchain_transaction_id == blockchain_transaction_id)
        if from_date:
            query = query.where(ComplianceRecord.submission_time >= from_date)
        if to_date:
            query = query.where(ComplianceRecord.submission_time <= to_date)

        results = session.exec(query).all()

        # artifact_type requires a join — filter in Python after query
        if artifact_type:
            artifact_ids = {
                a.id for a in session.exec(
                    select(Artifact).where(Artifact.artifact_type == artifact_type)
                ).all()
            }
            results = [r for r in results if r.artifact_id in artifact_ids]

        return results


# ==========================================
# 7. METRICS, AGGREGATIONS & MANAGEMENT REPORTS
# ==========================================

def _get_report_for_period(delta: timedelta):
    """Helper: aggregate compliance stats for a rolling time window."""
    with Session(engine) as session:
        boundary = datetime.now(timezone.utc) - delta
        total    = session.exec(select(func.count(ComplianceRecord.id)).where(ComplianceRecord.submission_time >= boundary)).one()
        verified = session.exec(select(func.count(ComplianceRecord.id)).where(ComplianceRecord.verification_status == "Verified").where(ComplianceRecord.submission_time >= boundary)).one()
        failed   = session.exec(select(func.count(ComplianceRecord.id)).where(ComplianceRecord.verification_status == "Failed").where(ComplianceRecord.submission_time >= boundary)).one()
        rate     = round((verified / total) * 100, 2) if total > 0 else 0.0
        return {
            "total_submissions": total,
            "verified": verified,
            "failed": failed,
            "success_rate_pct": rate
        }


@app.get("/api/dashboard", tags=["Dashboard"])
def get_dashboard_metrics(current_user=Depends(get_current_user)):
    """Main compliance dashboard — total apps, packages, success rate, and overall status."""
    with Session(engine) as session:
        total_apps     = session.exec(select(func.count(Application.id))).one()
        total_packages = session.exec(select(func.count(Artifact.id))).one()
        verified       = session.exec(select(func.count(Artifact.id)).where(Artifact.status == "Verified")).one()
        failed         = session.exec(select(func.count(Artifact.id)).where(Artifact.status.in_(["Hash Mismatch", "Corrupted", "Processing Failed"]))).one()
        blockchain_txs = session.exec(select(func.count(BlockchainRecord.id))).one()

        success_rate      = round((verified / total_packages) * 100, 2) if total_packages > 0 else 0.0
        compliance_status = "STABLE" if failed == 0 else "DEGRADED"

        return {
            "total_applications":   total_apps,
            "total_packages":       total_packages,
            "verified_packages":    verified,
            "failed_packages":      failed,
            "blockchain_transactions": blockchain_txs,
            "compliance_status":    compliance_status,
            "success_rate_pct":     success_rate
        }


@app.get("/api/reports/daily", tags=["Reports"])
def daily_compliance_report(current_user=Depends(get_current_user)):
    """Rolling 24-hour compliance summary."""
    return {"report_scope": "DAILY_24H", "generated_at": datetime.now(timezone.utc), "metrics": _get_report_for_period(timedelta(days=1))}


@app.get("/api/reports/monthly", tags=["Reports"])
def monthly_compliance_report(current_user=Depends(get_current_user)):
    """Rolling 30-day compliance summary."""
    return {"report_scope": "MONTHLY_30D", "generated_at": datetime.now(timezone.utc), "metrics": _get_report_for_period(timedelta(days=30))}


@app.get("/api/reports/audit", tags=["Reports"])
def audit_verification_report(current_user=Depends(get_current_user)):
    """Full compliance record snapshot for audit purposes."""
    with Session(engine) as session:
        records = session.exec(select(ComplianceRecord)).all()
        return {
            "scope": "AUDIT_VERIFICATION_FULL",
            "generated_at": datetime.now(timezone.utc),
            "total_records": len(records),
            "records": records
        }


@app.get("/api/reports/failures", tags=["Reports"])
def integrity_failure_report(current_user=Depends(get_current_user)):
    """All compliance records with a non-Verified status."""
    with Session(engine) as session:
        failures = session.exec(
            select(ComplianceRecord).where(
                ComplianceRecord.verification_status.in_(["Failed", "Corrupted", "Processing Failed"])
            )
        ).all()
        return {
            "scope": "INTEGRITY_FAILURE_EXCEPTIONS",
            "generated_at": datetime.now(timezone.utc),
            "total_breaches": len(failures),
            "breach_registry": failures
        }


@app.get("/api/compliance-summary", tags=["Dashboard"])
def get_executive_summary(current_user=Depends(get_current_user)):
    """High-level executive summary across all time."""
    with Session(engine) as session:
        total_apps      = session.exec(select(func.count(Application.id))).one()
        total_artifacts = session.exec(select(func.count(Artifact.id))).one()
        verified        = session.exec(select(func.count(Artifact.id)).where(Artifact.status == "Verified")).one()
        failed          = session.exec(select(func.count(Artifact.id)).where(Artifact.status.in_(["Hash Mismatch", "Corrupted", "Processing Failed"]))).one()
        blockchain_recs = session.exec(select(func.count(BlockchainRecord.id))).one()
        rate            = round((verified / total_artifacts) * 100, 2) if total_artifacts > 0 else 100.0

        return {
            "applications":      total_apps,
            "artifacts":         total_artifacts,
            "verified":          verified,
            "failed":            failed,
            "blockchain_records": blockchain_recs,
            "success_rate_pct":  rate
        }


# ==========================================
# 8. AUDIT TRAILS
# ==========================================

# FIX 5: Added /api/audit alias to match the spec exactly
@app.get("/api/audit", response_model=List[AuditLog], tags=["Audit"])
def get_audit_logs(current_user=Depends(require_role(["ADMINISTRATOR", "AUDITOR"]))):
    """
    Full immutable audit trail. Restricted to ADMINISTRATOR and AUDITOR roles.
    Matches the spec endpoint: GET /api/audit
    """
    with Session(engine) as session:
        return session.exec(select(AuditLog).order_by(AuditLog.timestamp.desc())).all()


@app.get("/api/audit-logs", response_model=List[AuditLog], tags=["Audit"])
def get_audit_logs_alias(current_user=Depends(require_role(["ADMINISTRATOR", "AUDITOR"]))):
    """Alias for /api/audit — kept for backward compatibility."""
    with Session(engine) as session:
        return session.exec(select(AuditLog).order_by(AuditLog.timestamp.desc())).all()


@app.get("/api/blockchain", response_model=List[BlockchainRecord], tags=["Blockchain"])
def get_blockchain_ledger(current_user=Depends(get_current_user)):
    """Returns all blockchain publication records."""
    with Session(engine) as session:
        return session.exec(select(BlockchainRecord).order_by(BlockchainRecord.timestamp.desc())).all()


@app.get("/api/compliance-records", response_model=List[ComplianceRecord], tags=["Compliance"])
def get_compliance_records(current_user=Depends(get_current_user)):
    """Returns all compliance records."""
    with Session(engine) as session:
        return session.exec(select(ComplianceRecord)).all()


# ==========================================
# 9. SIMULATION & TESTING UTILITIES
# ==========================================

@app.post("/api/verify/{artifact_id}/simulate-failure", tags=["Testing"])
def simulate_edge_case_failure(
    artifact_id: int,
    target_status: str = Query(..., description="Corrupted OR Processing Failed"),
    current_user=Depends(require_role(["ADMINISTRATOR", "AUDITOR"]))
):
    """
    Test utility: Forces an artifact into a specific failure state.
    Use during demos to show the Corrupted / Processing Failed status flows.
    """
    if target_status not in ["Corrupted", "Processing Failed"]:
        raise HTTPException(status_code=400, detail="target_status must be 'Corrupted' or 'Processing Failed'")

    with Session(engine) as session:
        artifact = session.get(Artifact, artifact_id)
        compliance_record = session.exec(
            select(ComplianceRecord).where(ComplianceRecord.artifact_id == artifact_id)
        ).first()

        if not artifact or not compliance_record:
            raise HTTPException(status_code=404, detail="Artifact or compliance record not found")

        artifact.status = target_status
        artifact.verification_time = datetime.now(timezone.utc)
        compliance_record.verification_status = target_status
        compliance_record.verification_time = datetime.now(timezone.utc)

        session.add(artifact)
        session.add(compliance_record)
        session.add(AuditLog(
            action=f"VERIFY_{target_status.upper().replace(' ', '_')}",
            artifact_id=artifact.id,
            performed_by=current_user.get("sub")
        ))
        session.commit()

        return {"status": "Simulated failure set", "artifact_id": artifact_id, "new_status": artifact.status}


@app.post("/api/auth/simulate-logout", tags=["Authentication"])
def simulate_user_logout(
    username: str,
    current_user=Depends(get_current_user)
):
    """Logs a logout event to the audit trail."""
    with Session(engine) as session:
        session.add(AuditLog(
            action="LOGOUT",
            performed_by=username
        ))
        session.commit()
        return {"status": "Logout logged", "user": username}


@app.post("/api/system/simulate-config-change", tags=["Testing"])
def simulate_config_change(
    parameter: str,
    value: str,
    current_user=Depends(require_role(["ADMINISTRATOR"]))
):
    """Logs a configuration change event. ADMINISTRATOR only."""
    with Session(engine) as session:
        session.add(AuditLog(
            action=f"CONFIG_CHANGE - {parameter} = {value}",
            performed_by=current_user.get("sub")
        ))
        session.commit()
        return {"status": "Configuration change logged", "parameter": parameter, "value": value}