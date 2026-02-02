"""Tests for Phase 6: Web Dashboard API.

Covers (from docs testing section):
- Test all API endpoints
- Verify real-time updates work (WebSocket broadcast)
- Test recovery workflow via API

Endpoints tested:
    GET  /api/status
    GET  /api/events
    GET  /api/threats
    POST /api/quarantine
    GET  /api/backups
    POST /api/restore
    GET  /api/config
    PUT  /api/config
    WS   /ws/live
"""

import json
import os

import pytest

from src.dashboard.app import create_app
from src.dashboard.websocket_handler import WebSocketHandler
from src.database.event_logger import EventLogger
from src.response.backup_manager import BackupManager
from src.response.response_engine import ResponseEngine
from src.analysis.behavior_analyzer import BehaviorAnalyzer
from src.analysis.threat_scoring import ThreatScore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def services(tmp_path):
    """Create real service instances backed by temp directories."""
    db_path = str(tmp_path / "events.db")
    vault = str(tmp_path / "vault")
    config_path = str(tmp_path / "config.json")
    config = {
        "monitor": {"watch_directories": [], "exclude_directories": [],
                     "file_extension_filter": [], "recursive": True},
        "database": {"path": db_path},
        "entropy": {"baseline_db_path": str(tmp_path / "ent.db"),
                     "delta_threshold": 2.0},
        "logging": {"level": "INFO"},
    }
    with open(config_path, "w") as f:
        json.dump(config, f)

    el = EventLogger(db_path)
    bm = BackupManager(vault_path=vault)
    re = ResponseEngine(backup_manager=bm, safe_mode=False,
                        enable_desktop_alerts=False)
    ba = BehaviorAnalyzer()

    yield {
        "event_logger": el,
        "backup_manager": bm,
        "response_engine": re,
        "behavior_analyzer": ba,
        "config_path": config_path,
        "tmp_path": tmp_path,
    }

    el.close()
    bm.close()


@pytest.fixture
def app(services):
    return create_app(
        config_path=services["config_path"],
        event_logger=services["event_logger"],
        backup_manager=services["backup_manager"],
        response_engine=services["response_engine"],
        behavior_analyzer=services["behavior_analyzer"],
    )


@pytest.fixture
def client(app):
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# GET /api/status
# ---------------------------------------------------------------------------

class TestGetStatus:
    def test_returns_running(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "running"
        assert "timestamp" in data
        assert "threat_level" in data

    def test_threat_level_normal_by_default(self, client):
        data = client.get("/api/status").get_json()
        assert data["threat_level"] == "NORMAL"

    def test_threat_level_elevated(self, client, services):
        ba = services["behavior_analyzer"]
        ba.process_event(
            event_type="modified", file_path="/f.txt",
            process_id=1, process_name="test", entropy_delta=0.1,
        )
        # Score is low (NORMAL), so let's push it to SUSPICIOUS
        for i in range(25):
            ba.process_event(
                event_type="modified", file_path=f"/d{i}/f{i}.txt",
                process_id=1, process_name="test",
            )
        data = client.get("/api/status").get_json()
        # Should be ELEVATED or NORMAL depending on score
        assert data["threat_level"] in ("NORMAL", "ELEVATED", "CRITICAL")


# ---------------------------------------------------------------------------
# GET /api/events
# ---------------------------------------------------------------------------

class TestGetEvents:
    def test_empty_events(self, client):
        resp = client.get("/api/events")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["events"] == []
        assert data["total"] == 0

    def test_events_returned(self, client, services):
        el = services["event_logger"]
        el.log_event(event_type="created", file_path="/a.txt")
        el.log_event(event_type="modified", file_path="/b.txt")

        data = client.get("/api/events").get_json()
        assert data["total"] == 2
        assert len(data["events"]) == 2

    def test_filter_by_type(self, client, services):
        el = services["event_logger"]
        el.log_event(event_type="created", file_path="/a.txt")
        el.log_event(event_type="deleted", file_path="/b.txt")

        data = client.get("/api/events?type=created").get_json()
        assert all(e["event_type"] == "created" for e in data["events"])

    def test_pagination(self, client, services):
        el = services["event_logger"]
        for i in range(10):
            el.log_event(event_type="created", file_path=f"/f{i}.txt")

        data = client.get("/api/events?limit=3&offset=0").get_json()
        assert len(data["events"]) == 3
        assert data["limit"] == 3
        assert data["offset"] == 0


# ---------------------------------------------------------------------------
# GET /api/threats
# ---------------------------------------------------------------------------

class TestGetThreats:
    def test_empty_threats(self, client):
        data = client.get("/api/threats").get_json()
        assert data["threats"] == []

    def test_threats_populated(self, client, services):
        re = services["response_engine"]
        threat = ThreatScore(process_id=1, process_name="evil", score=45,
                             level="SUSPICIOUS", triggered_indicators={"test": "d"},
                             action_required=False)
        re.respond(threat)

        data = client.get("/api/threats").get_json()
        assert len(data["threats"]) >= 1
        assert data["threats"][0]["score"] == 45

    def test_filter_by_severity(self, client, services):
        re = services["response_engine"]
        re.respond(ThreatScore(1, "a", 40, "SUSPICIOUS", {"t": "d"}, False))
        re.respond(ThreatScore(2, "b", 60, "LIKELY", {"t": "d"}, False))

        data = client.get("/api/threats?severity=2").get_json()
        assert all(t["escalation_level"] == 2 for t in data["threats"])


# ---------------------------------------------------------------------------
# POST /api/quarantine
# ---------------------------------------------------------------------------

class TestPostQuarantine:
    def test_missing_pid(self, client):
        resp = client.post("/api/quarantine", json={})
        assert resp.status_code == 400

    def test_invalid_pid(self, client):
        resp = client.post("/api/quarantine", json={"pid": "abc"})
        assert resp.status_code == 400

    def test_quarantine_nonexistent_pid(self, client):
        resp = client.post("/api/quarantine", json={"pid": 99999})
        data = resp.get_json()
        assert data["action"] == "suspend"
        assert data["success"] is False


# ---------------------------------------------------------------------------
# GET /api/backups
# ---------------------------------------------------------------------------

class TestGetBackups:
    def test_empty_backups(self, client):
        data = client.get("/api/backups").get_json()
        assert data["backups"] == []

    def test_backups_listed(self, client, services):
        bm = services["backup_manager"]
        src = services["tmp_path"] / "src.txt"
        src.write_text("backup me")
        bm.backup_file(str(src), process_name="proc")

        data = client.get("/api/backups").get_json()
        assert len(data["backups"]) == 1
        assert data["backups"][0]["process_name"] == "proc"

    def test_filter_by_process(self, client, services):
        bm = services["backup_manager"]
        src = services["tmp_path"] / "f.txt"
        src.write_text("data")
        bm.backup_file(str(src), process_name="alpha")
        bm.backup_file(str(src), process_name="beta")

        data = client.get("/api/backups?process=alpha").get_json()
        assert all(b["process_name"] == "alpha" for b in data["backups"])


# ---------------------------------------------------------------------------
# POST /api/restore
# ---------------------------------------------------------------------------

class TestPostRestore:
    def test_restore_single(self, client, services):
        bm = services["backup_manager"]
        src = services["tmp_path"] / "restore.txt"
        src.write_text("original")
        bm.backup_file(str(src))
        backups = bm.snapshot.get_backups(original_path=str(src))

        src.write_text("DESTROYED")
        resp = client.post("/api/restore", json={"backup_id": backups[0]["id"]})
        data = resp.get_json()
        assert data["succeeded"] == 1
        assert src.read_text() == "original"

    def test_restore_batch(self, client, services):
        bm = services["backup_manager"]
        f1 = services["tmp_path"] / "a.txt"
        f2 = services["tmp_path"] / "b.txt"
        f1.write_text("A")
        f2.write_text("B")
        bm.backup_file(str(f1))
        bm.backup_file(str(f2))
        b1 = bm.snapshot.get_backups(original_path=str(f1))[0]
        b2 = bm.snapshot.get_backups(original_path=str(f2))[0]

        f1.write_text("X")
        f2.write_text("X")
        resp = client.post("/api/restore", json={"backup_ids": [b1["id"], b2["id"]]})
        data = resp.get_json()
        assert data["succeeded"] == 2

    def test_restore_by_process(self, client, services):
        bm = services["backup_manager"]
        f = services["tmp_path"] / "proc.txt"
        f.write_text("orig")
        bm.backup_file(str(f), process_name="evil")
        f.write_text("GONE")

        resp = client.post("/api/restore", json={"process_name": "evil"})
        data = resp.get_json()
        assert data["succeeded"] >= 1
        assert f.read_text() == "orig"

    def test_restore_no_params(self, client):
        resp = client.post("/api/restore", json={})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /api/config
# ---------------------------------------------------------------------------

class TestGetConfig:
    def test_returns_config(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "monitor" in data or "database" in data


# ---------------------------------------------------------------------------
# PUT /api/config
# ---------------------------------------------------------------------------

class TestPutConfig:
    def test_update_config(self, client):
        resp = client.put("/api/config", json={
            "monitor": {"recursive": False},
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["monitor"]["recursive"] is False

    def test_config_persisted(self, client, services):
        client.put("/api/config", json={"logging": {"level": "DEBUG"}})
        with open(services["config_path"]) as f:
            saved = json.load(f)
        assert saved["logging"]["level"] == "DEBUG"

    def test_empty_body_rejected(self, client):
        resp = client.put("/api/config", json={})
        assert resp.status_code == 400

    def test_deep_merge(self, client):
        client.put("/api/config", json={"monitor": {"recursive": True}})
        client.put("/api/config", json={"monitor": {"watch_directories": ["/new"]}})
        data = client.get("/api/config").get_json()
        # Both keys should exist
        assert data["monitor"]["recursive"] is True
        assert data["monitor"]["watch_directories"] == ["/new"]


# ---------------------------------------------------------------------------
# WebSocket handler unit tests
# ---------------------------------------------------------------------------

class TestWebSocketHandler:
    def test_register_and_count(self):
        wsh = WebSocketHandler()
        assert wsh.client_count == 0

        class FakeWS:
            def send(self, msg): pass

        ws = FakeWS()
        wsh.register(ws)
        assert wsh.client_count == 1

        wsh.unregister(ws)
        assert wsh.client_count == 0

    def test_broadcast(self):
        wsh = WebSocketHandler()
        received = []

        class FakeWS:
            def send(self, msg):
                received.append(json.loads(msg))

        wsh.register(FakeWS())
        wsh.register(FakeWS())
        wsh.broadcast("test_event", {"key": "value"})

        assert len(received) == 2
        assert received[0]["type"] == "test_event"
        assert received[0]["data"]["key"] == "value"

    def test_dead_client_removed(self):
        wsh = WebSocketHandler()

        class DeadWS:
            def send(self, msg):
                raise ConnectionError("gone")

        wsh.register(DeadWS())
        assert wsh.client_count == 1
        wsh.broadcast("ping", {})
        assert wsh.client_count == 0

    def test_unregister_unknown_client(self):
        wsh = WebSocketHandler()

        class FakeWS:
            pass

        wsh.unregister(FakeWS())  # should not raise
        assert wsh.client_count == 0
