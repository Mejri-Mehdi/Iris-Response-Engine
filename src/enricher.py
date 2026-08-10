# src/enricher.py
from __future__ import annotations

import datetime
import json
import logging
from typing import Any, Dict, Optional

from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from src.models import Base   # shared declarative base

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQLAlchemy model for the intel cache table (matches spec exactly)
# ---------------------------------------------------------------------------
class IntelCache(Base):
    __tablename__ = "intel_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    query = Column(String(255), nullable=False)
    source = Column(String(50), nullable=False)
    result = Column(Text, nullable=False)          # stored as JSON string
    cached_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Composite index for fast lookups
    __table_args__ = (
        Index("ix_intel_cache_query_source", "query", "source", unique=True),
    )

    def __repr__(self):
        return f"<IntelCache {self.source}:{self.query[:20]}>"


# ---------------------------------------------------------------------------
# Cache helper class
# ---------------------------------------------------------------------------
class ThreatIntelCache:
    """
    Wraps the intel_cache table.
    Accepts a session factory or a session object (used within an active session).
    """

    def __init__(self, session: Session):
        self.session = session

    def get(self, query: str, source: str) -> Optional[Dict[str, Any]]:
        """Return cached result if it's less than 1 hour old."""
        one_hour_ago = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        cached = (
            self.session.query(IntelCache)
            .filter(
                IntelCache.query == query,
                IntelCache.source == source,
                IntelCache.cached_at >= one_hour_ago,
            )
            .first()
        )
        if cached:
            return json.loads(cached.result)
        return None

    def set(self, query: str, source: str, result: Dict[str, Any]) -> None:
        """Insert or update the cached entry."""
        existing = (
            self.session.query(IntelCache)
            .filter_by(query=query, source=source)
            .first()
        )
        if existing:
            existing.result = json.dumps(result)
            existing.cached_at = datetime.datetime.utcnow()
        else:
            entry = IntelCache(
                query=query,
                source=source,
                result=json.dumps(result),
                cached_at=datetime.datetime.utcnow(),
            )
            self.session.add(entry)
        self.session.commit()


# ---------------------------------------------------------------------------
# Main Enricher
# ---------------------------------------------------------------------------
class Enricher:
    """
    Mock threat intel enricher with deterministic answers and caching.
    """

    def __init__(self, session: Session):
        self.session = session
        self.cache = ThreatIntelCache(session)

    # -------------------------------------------------------------------
    # Lookup methods
    # -------------------------------------------------------------------

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """VirusTotal-style file hash lookup."""
        cached = self.cache.get(file_hash, "virustotal")
        if cached:
            return cached

        # Deterministic mock based on first character
        first_char = file_hash[0].lower() if file_hash else ""
        if first_char in ("a", "f"):
            result = {
                "verdict": "malicious",
                "detection_ratio": "15/70",
                "threat_label": "Trojan.Win32.Generic",
                "first_seen": "2024-01-15",
                "last_analysis": "2026-08-08",
            }
        elif first_char in ("c", "d"):
            result = {
                "verdict": "suspicious",
                "detection_ratio": "3/68",
                "threat_label": "PUP.Win32.Adware",
                "first_seen": "2025-06-01",
                "last_analysis": "2026-08-08",
            }
        else:
            result = {
                "verdict": "clean",
                "detection_ratio": "0/70",
                "threat_label": "",
                "first_seen": "",
                "last_analysis": "2026-08-08",
            }

        self.cache.set(file_hash, "virustotal", result)
        return result

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """IP reputation lookup."""
        cached = self.cache.get(ip_address, "ip_reputation")
        if cached:
            return cached

        # Deterministic based on first octet
        try:
            first_octet = int(ip_address.split(".")[0])
        except (IndexError, ValueError):
            first_octet = 0

        if first_octet in (185, 45, 103):
            result = {
                "country": "RU",
                "asn": "AS44477",
                "reputation": "malicious",
                "known_as": "CobaltStrike",
            }
        elif first_octet in (192, 10):
            result = {
                "country": "US",
                "asn": "AS15169",
                "reputation": "clean",
                "known_as": None,
            }
        elif first_octet == 91:
            result = {
                "country": "NL",
                "asn": "AS16276",
                "reputation": "suspicious",
                "known_as": "TrickBot",
            }
        else:
            result = {
                "country": "CN",
                "asn": "AS4837",
                "reputation": "suspicious",
                "known_as": None,
            }

        self.cache.set(ip_address, "ip_reputation", result)
        return result

    def lookup_url(self, url: str) -> Dict[str, Any]:
        """Phishing / malware URL check."""
        cached = self.cache.get(url, "url_reputation")
        if cached:
            return cached

        # Simple heuristics on URL content
        is_phishing = "login" in url or "verify" in url or "secure" in url
        is_malware = "exe" in url or "dll" in url or "payload" in url
        is_suspicious = is_phishing or is_malware

        result = {
            "phishing": is_phishing,
            "malware": is_malware,
            "suspicious": is_suspicious,
            "source": "mock_abuse_ch",
        }

        self.cache.set(url, "url_reputation", result)
        return result

    def geoip(self, ip_address: str) -> Dict[str, Any]:
        """Geolocation data for an IP address."""
        cached = self.cache.get(ip_address, "geoip")
        if cached:
            return cached

        # Deterministic based on first octet (simplified)
        try:
            first_octet = int(ip_address.split(".")[0])
        except (IndexError, ValueError):
            first_octet = 0

        if first_octet in (185, 45, 103):
            result = {
                "latitude": 55.7558,
                "longitude": 37.6173,
                "city": "Moscow",
                "country": "RU",
            }
        elif first_octet in (192, 10):
            result = {
                "latitude": 37.7749,
                "longitude": -122.4194,
                "city": "San Francisco",
                "country": "US",
            }
        elif first_octet == 91:
            result = {
                "latitude": 52.3676,
                "longitude": 4.9041,
                "city": "Amsterdam",
                "country": "NL",
            }
        else:
            result = {
                "latitude": 35.8617,
                "longitude": 104.1954,
                "city": "Beijing",
                "country": "CN",
            }

        self.cache.set(ip_address, "geoip", result)
        return result