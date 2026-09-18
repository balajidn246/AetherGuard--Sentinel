import pytest
import asyncio
from datetime import datetime, timezone
from backend.models.events import OCSFBaseEvent
from backend.pipeline.entity_extractor import EntityExtractor
from backend.pipeline.entity_normalizer import EntityNormalizer

def test_entity_normalization():
    # IP
    can, disp = EntityNormalizer.normalize_ip("192.168.1.1")
    assert can == "192.168.1.1"
    
    # Domain
    can, disp = EntityNormalizer.normalize_domain("ExAmPlE.com.")
    assert can == "example.com"
    
    # Hash
    can, disp = EntityNormalizer.normalize_hash("AABB1122")
    assert can == "aabb1122"
    
    # Username
    can, disp = EntityNormalizer.normalize_username("DOMAIN\\User1")
    assert can == "user1"

def test_entity_extraction():
    event = OCSFBaseEvent(
        tenant_id="tenant-x",
        class_name="Authentication",
        user_name="DOMAIN\\Admin",
        src_ip="10.0.0.5",
        host_name="server01.local"
    )
    
    entities, rels = EntityExtractor.extract(event)
    
    assert len(entities) == 3
    types = set(e.entity_type for e in entities)
    assert types == {"ip", "user", "host"}
    
    # Should have 2 relationships: user->host, user->ip
    assert len(rels) == 2
    rel_types = set(r.relation_type for r in rels)
    assert rel_types == {"logged_in_to", "logged_in_from"}
    
    # Check provenance
    for r in rels:
        assert r.source_log == "api"
        assert r.event_id == str(event.event_id)
        assert r.tenant_id == "tenant-x"
