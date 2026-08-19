# tests/test_enricher.py
import datetime
import json

from src.enricher import Enricher, IntelCache, ThreatIntelCache


def test_lookup_hash_deterministic(session):
    enricher = Enricher(session)
    # Hash starting with 'a' should be malicious
    result = enricher.lookup_hash("abc123")
    assert result["verdict"] == "malicious"
    assert result["threat_label"] == "Trojan.Win32.Generic"
    # Hash starting with 'c' should be suspicious
    result = enricher.lookup_hash("cde456")
    assert result["verdict"] == "suspicious"
    # Hash starting with 'x' should be clean
    result = enricher.lookup_hash("xyz789")
    assert result["verdict"] == "clean"


def test_lookup_ip_deterministic(session):
    enricher = Enricher(session)
    result = enricher.lookup_ip("185.20.30.40")
    assert result["reputation"] == "malicious"
    assert result["country"] == "RU"
    result = enricher.lookup_ip("192.168.1.1")
    assert result["reputation"] == "clean"
    result = enricher.lookup_ip("91.10.20.30")
    assert result["reputation"] == "suspicious"


def test_cache_store_and_retrieve(session):
    enricher = Enricher(session)
    hash_val = "abc123"
    first = enricher.lookup_hash(hash_val)
    # Second call should hit cache and return same result
    second = enricher.lookup_hash(hash_val)
    assert first == second
    # Verify cache entry exists
    cache_entry = session.query(IntelCache).filter_by(query=hash_val, source="virustotal").first()
    assert cache_entry is not None


def test_cache_expiration(session):
    enricher = Enricher(session)
    hash_val = "abc123"
    enricher.lookup_hash(hash_val)
    # Manually age the cache entry
    entry = session.query(IntelCache).filter_by(query=hash_val, source="virustotal").first()
    entry.cached_at = datetime.datetime.utcnow() - datetime.timedelta(hours=2)
    session.commit()
    # Now lookup should re-fetch (but still deterministic same result)
    result = enricher.lookup_hash(hash_val)
    assert result["verdict"] == "malicious"


def test_geoip(session):
    enricher = Enricher(session)
    result = enricher.geoip("185.20.30.40")
    assert result["country"] == "RU"
    assert result["city"] == "Moscow"