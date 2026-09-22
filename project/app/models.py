from datetime import datetime, timezone

from pgvector.sqlalchemy import Vector
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.config import get_settings

EMBEDDING_DIM = get_settings().embedding_dim


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Crash(Base):
    __tablename__ = "crashes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(50))
    raw_log: Mapped[str] = mapped_column(Text)
    bug_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    syzbot_fixed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    patch_status: Mapped[str] = mapped_column(String(20), default="unknown")
    status: Mapped[str] = mapped_column(String(20), default="분석 대기")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBEDDING_DIM), nullable=True)
    vmlinux_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    disk_image_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    kernel_image_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    syzbot_extid: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)

    poc_links: Mapped[list["CrashPoCLink"]] = relationship(back_populates="crash")


class CVE(Base):
    __tablename__ = "cves"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(30), unique=True)
    description: Mapped[str] = mapped_column(Text)
    cpe_match: Mapped[str | None] = mapped_column(Text, nullable=True)
    patched: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBEDDING_DIM), nullable=True)


class PoC(Base):
    __tablename__ = "pocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_url: Mapped[str] = mapped_column(String(500), unique=True)
    cve_ref: Mapped[str | None] = mapped_column(String(30), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBEDDING_DIM), nullable=True)


class CrashPoCLink(Base):
    __tablename__ = "crash_poc_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    crash_id: Mapped[int] = mapped_column(ForeignKey("crashes.id"))
    poc_id: Mapped[int] = mapped_column(ForeignKey("pocs.id"))
    similarity_score: Mapped[float] = mapped_column(Float)

    crash: Mapped["Crash"] = relationship(back_populates="poc_links")


class CollectionError(Base):
    __tablename__ = "collection_errors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(50))
    reason: Mapped[str] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
