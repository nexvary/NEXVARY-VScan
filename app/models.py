from __future__ import annotations
from datetime import datetime
import secrets
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(30), default="analyst")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    url: Mapped[str] = mapped_column(String(500))
    owner: Mapped[str] = mapped_column(String(120))
    verification_token: Mapped[str] = mapped_column(String(80), default=lambda: secrets.token_urlsafe(24))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    requests: Mapped[list["ScanRequest"]] = relationship(back_populates="target")

class ScanRequest(Base):
    __tablename__ = "scan_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    requested_by: Mapped[str] = mapped_column(String(120))
    approved_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    approval_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    security_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pages_crawled: Mapped[int] = mapped_column(Integer, default=0)
    requests_made: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    target: Mapped[Target] = relationship(back_populates="requests")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_request", cascade="all, delete-orphan")
    surface_items: Mapped[list["SurfaceItem"]] = relationship(back_populates="scan_request", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_request_id: Mapped[int] = mapped_column(ForeignKey("scan_requests.id"))
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    detail: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    endpoint: Mapped[str | None] = mapped_column(String(700), nullable=True)
    confirmed: Mapped[bool] = mapped_column(Boolean, default=True)
    confidence: Mapped[str] = mapped_column(String(20), default="High")
    category: Mapped[str] = mapped_column(String(80), default="Web Security")
    evidence: Mapped[str] = mapped_column(Text, default="")
    cwe: Mapped[str | None] = mapped_column(String(40), nullable=True)
    owasp: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scan_request: Mapped[ScanRequest] = relationship(back_populates="findings")

class SurfaceItem(Base):
    __tablename__ = "surface_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_request_id: Mapped[int] = mapped_column(ForeignKey("scan_requests.id"))
    category: Mapped[str] = mapped_column(String(40), index=True)
    value: Mapped[str] = mapped_column(String(900))
    source_endpoint: Mapped[str | None] = mapped_column(String(900), nullable=True)
    method: Mapped[str | None] = mapped_column(String(12), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    scan_request: Mapped[ScanRequest] = relationship(back_populates="surface_items")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(160))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
