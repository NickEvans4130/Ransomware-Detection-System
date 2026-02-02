"""Tests for Phase 4: Backup/Snapshot System (Option A - Simple File Versioning).

Covers (from docs testing section):
- Modify files and verify backups created
- Test restoration accuracy
- Verify backup isolation (permissions)
- Test storage cleanup (48-hour retention)
- Performance impact measurement
- Database schema validation
- Metadata tracking (original path, timestamp, SHA-256, reason)
- Recovery: by path, by process, point-in-time, integrity verification
"""

import hashlib
import json
import os
import stat
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.response.backup_config import (
    RETENTION_HOURS,
    VAULT_DIR_MODE,
    VAULT_FILE_MODE,
    SNAPSHOT_DIR_FORMAT,
)
from src.response.snapshot_service import (
    SnapshotService,
    file_sha256,
    flatten_path,
)
from src.response.recovery_manager import RecoveryManager, RestoreResult
from src.response.backup_manager import BackupManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def vault(tmp_path):
    return str(tmp_path / "vault")


@pytest.fixture
def source_dir(tmp_path):
    d = tmp_path / "source"
    d.mkdir()
    return d


@pytest.fixture
def snapshot_svc(vault):
    svc = SnapshotService(vault_path=vault)
    yield svc
    svc.close()


@pytest.fixture
def backup_mgr(vault):
    mgr = BackupManager(vault_path=vault)
    yield mgr
    mgr.close()


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------

class TestFlattenPath:
    def test_unix_path(self):
        assert flatten_path("/home/user/Documents/report.docx") == \
            "home_user_Documents_report.docx"

    def test_windows_style_path(self):
        result = flatten_path("C:\\Users\\student\\file.txt")
        assert "C_Users_student_file.txt" in result.replace("\\", "_")

    def test_no_leading_separator(self):
        result = flatten_path("/a/b/c.txt")
        assert not result.startswith("_")


class TestFileSha256:
    def test_correct_hash(self, source_dir):
        p = source_dir / "hash_me.txt"
        p.write_text("hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert file_sha256(str(p)) == expected

    def test_nonexistent_returns_none(self):
        assert file_sha256("/no/such/file") is None


# ---------------------------------------------------------------------------
# Snapshot creation & metadata
# ---------------------------------------------------------------------------

class TestSnapshotCreation:
    def test_backup_file_created(self, snapshot_svc, source_dir):
        src = source_dir / "doc.txt"
        src.write_text("important data")
        result = snapshot_svc.create_snapshot(str(src), reason="test")

        assert result is not None
        assert os.path.isfile(result["backup_path"])

    def test_backup_content_matches(self, snapshot_svc, source_dir):
        src = source_dir / "exact.txt"
        content = "preserve this exactly"
        src.write_text(content)
        result = snapshot_svc.create_snapshot(str(src))

        with open(result["backup_path"]) as f:
            assert f.read() == content

    def test_metadata_fields(self, snapshot_svc, source_dir):
        src = source_dir / "meta.txt"
        src.write_text("metadata test")
        result = snapshot_svc.create_snapshot(
            str(src), reason="suspicious", process_name="evil.exe",
        )

        assert result["original_path"] == str(src)
        assert result["timestamp"] is not None
        assert result["file_hash"] is not None
        assert result["reason"] == "suspicious"
        assert result["process_name"] == "evil.exe"

    def test_sha256_integrity(self, snapshot_svc, source_dir):
        src = source_dir / "integrity.bin"
        src.write_bytes(b"\x00\x01\x02" * 100)
        result = snapshot_svc.create_snapshot(str(src))

        expected = hashlib.sha256(b"\x00\x01\x02" * 100).hexdigest()
        assert result["file_hash"] == expected

    def test_metadata_json_written(self, snapshot_svc, source_dir):
        src = source_dir / "mjson.txt"
        src.write_text("test")
        result = snapshot_svc.create_snapshot(str(src), reason="routine")

        snapshot_dir = os.path.dirname(result["backup_path"])
        meta_path = os.path.join(snapshot_dir, "metadata.json")
        assert os.path.isfile(meta_path)

        entries = json.loads(Path(meta_path).read_text())
        assert len(entries) >= 1
        assert entries[0]["original_path"] == str(src)
        assert entries[0]["sha256"] == result["file_hash"]

    def test_nonexistent_source_returns_none(self, snapshot_svc):
        assert snapshot_svc.create_snapshot("/no/such/file.txt") is None

    def test_directory_skipped(self, snapshot_svc, source_dir):
        assert snapshot_svc.create_snapshot(str(source_dir)) is None


# ---------------------------------------------------------------------------
# Database schema (from docs)
# ---------------------------------------------------------------------------

class TestDatabaseSchema:
    def test_schema_columns(self, snapshot_svc, vault):
        import sqlite3
        conn = sqlite3.connect(os.path.join(vault, "index.db"))
        cursor = conn.execute("PRAGMA table_info(backups)")
        columns = {row[1] for row in cursor.fetchall()}
        conn.close()

        required = {
            "id", "original_path", "backup_path",
            "timestamp", "file_hash", "reason", "process_name",
        }
        assert required.issubset(columns)

    def test_record_persisted(self, snapshot_svc, source_dir):
        src = source_dir / "db_test.txt"
        src.write_text("persist me")
        snapshot_svc.create_snapshot(str(src), reason="test", process_name="proc")

        backups = snapshot_svc.get_backups(original_path=str(src))
        assert len(backups) == 1
        assert backups[0]["reason"] == "test"
        assert backups[0]["process_name"] == "proc"


# ---------------------------------------------------------------------------
# Backup vault structure
# ---------------------------------------------------------------------------

class TestVaultStructure:
    def test_timestamped_subdirectory(self, snapshot_svc, source_dir):
        src = source_dir / "struct.txt"
        src.write_text("structure test")
        result = snapshot_svc.create_snapshot(str(src))

        snapshot_dir = Path(result["backup_path"]).parent
        # Directory name should match timestamp format
        name = snapshot_dir.name
        # Validate it parses as a datetime
        datetime.strptime(name, SNAPSHOT_DIR_FORMAT)

    def test_flattened_filename(self, snapshot_svc, source_dir):
        src = source_dir / "subdir" / "nested" / "deep.txt"
        src.parent.mkdir(parents=True)
        src.write_text("deep file")
        result = snapshot_svc.create_snapshot(str(src))

        backup_name = os.path.basename(result["backup_path"])
        # Should not contain path separators
        assert os.sep not in backup_name
        assert "/" not in backup_name


# ---------------------------------------------------------------------------
# Secure storage (permissions)
# ---------------------------------------------------------------------------

class TestSecureStorage:
    @pytest.mark.skipif(
        os.name == "nt", reason="Unix permissions not applicable on Windows",
    )
    def test_vault_permissions(self, snapshot_svc, vault):
        mode = stat.S_IMODE(os.stat(vault).st_mode)
        assert mode == VAULT_DIR_MODE

    @pytest.mark.skipif(
        os.name == "nt", reason="Unix permissions not applicable on Windows",
    )
    def test_backup_file_permissions(self, snapshot_svc, source_dir):
        src = source_dir / "secure.txt"
        src.write_text("secret")
        result = snapshot_svc.create_snapshot(str(src))

        mode = stat.S_IMODE(os.stat(result["backup_path"]).st_mode)
        assert mode == VAULT_FILE_MODE


# ---------------------------------------------------------------------------
# Recovery: individual file
# ---------------------------------------------------------------------------

class TestRecoveryIndividual:
    def test_restore_by_id(self, backup_mgr, source_dir):
        src = source_dir / "restore_me.txt"
        src.write_text("original content")
        backup_mgr.backup_file(str(src))

        # Simulate destruction
        src.write_text("ENCRYPTED GARBAGE")

        backups = backup_mgr.snapshot.get_backups(original_path=str(src))
        result = backup_mgr.recovery.restore_file(backups[0]["id"])

        assert result.success is True
        assert result.integrity_ok is True
        assert src.read_text() == "original content"

    def test_restore_missing_backup_id(self, backup_mgr):
        result = backup_mgr.recovery.restore_file(99999)
        assert result.success is False
        assert "not found" in result.error


class TestRecoveryByPath:
    def test_latest_only(self, backup_mgr, source_dir):
        src = source_dir / "versioned.txt"
        src.write_text("v1")
        backup_mgr.backup_file(str(src))
        time.sleep(0.05)
        src.write_text("v2")
        backup_mgr.backup_file(str(src))

        src.write_text("DESTROYED")
        results = backup_mgr.recovery.restore_by_path(str(src), latest=True)
        assert len(results) == 1
        assert results[0].success is True
        assert src.read_text() == "v2"

    def test_no_backups_found(self, backup_mgr):
        results = backup_mgr.recovery.restore_by_path("/nonexistent.txt")
        assert len(results) == 1
        assert results[0].success is False


class TestRecoveryByProcess:
    def test_restore_all_for_process(self, backup_mgr, source_dir):
        a = source_dir / "a.txt"
        b = source_dir / "b.txt"
        a.write_text("file A")
        b.write_text("file B")
        backup_mgr.backup_file(str(a), process_name="ransomware.exe")
        backup_mgr.backup_file(str(b), process_name="ransomware.exe")

        a.write_text("ENCRYPTED")
        b.write_text("ENCRYPTED")

        results = backup_mgr.recovery.restore_by_process("ransomware.exe")
        assert all(r.success for r in results)
        assert a.read_text() == "file A"
        assert b.read_text() == "file B"


class TestRecoveryPointInTime:
    def test_restore_since_timestamp(self, backup_mgr, source_dir):
        before = datetime.now().isoformat()
        time.sleep(0.05)

        f = source_dir / "pit.txt"
        f.write_text("point-in-time")
        backup_mgr.backup_file(str(f))

        f.write_text("GONE")
        results = backup_mgr.recovery.restore_point_in_time(before)
        assert len(results) >= 1
        assert any(r.success and r.original_path == str(f) for r in results)
        assert f.read_text() == "point-in-time"


class TestIntegrityVerification:
    def test_verify_intact_backup(self, backup_mgr, source_dir):
        src = source_dir / "verify.txt"
        src.write_text("intact")
        backup_mgr.backup_file(str(src))
        backups = backup_mgr.snapshot.get_backups(original_path=str(src))

        ok = backup_mgr.recovery.verify_backup(backups[0]["id"])
        assert ok is True

    def test_verify_corrupted_backup(self, backup_mgr, source_dir):
        src = source_dir / "corrupt.txt"
        src.write_text("will be corrupted")
        backup_mgr.backup_file(str(src))
        backups = backup_mgr.snapshot.get_backups(original_path=str(src))

        # Corrupt the backup file
        with open(backups[0]["backup_path"], "w") as f:
            f.write("CORRUPTED")

        ok = backup_mgr.recovery.verify_backup(backups[0]["id"])
        assert ok is False

    def test_corrupted_backup_not_restored(self, backup_mgr, source_dir):
        src = source_dir / "norestore.txt"
        src.write_text("original")
        backup_mgr.backup_file(str(src))
        backups = backup_mgr.snapshot.get_backups(original_path=str(src))

        with open(backups[0]["backup_path"], "w") as f:
            f.write("TAMPERED")

        src.write_text("destroyed")
        result = backup_mgr.recovery.restore_file(backups[0]["id"])
        assert result.success is False
        assert result.integrity_ok is False
        # Original should NOT have been overwritten with tampered data
        assert src.read_text() == "destroyed"


# ---------------------------------------------------------------------------
# 48-hour retention policy
# ---------------------------------------------------------------------------

class TestRetentionPolicy:
    def test_old_backups_removed(self, vault, source_dir):
        mgr = BackupManager(vault_path=vault, retention_hours=48)
        src = source_dir / "old.txt"
        src.write_text("old data")

        # Create a snapshot with a timestamp 49 hours ago
        old_ts = datetime.now() - timedelta(hours=49)
        mgr.snapshot.create_snapshot(
            str(src), reason="old", timestamp=old_ts,
        )
        assert len(mgr.snapshot.get_backups()) == 1

        mgr.enforce_retention()
        assert len(mgr.snapshot.get_backups()) == 0
        mgr.close()

    def test_recent_backups_kept(self, vault, source_dir):
        mgr = BackupManager(vault_path=vault, retention_hours=48)
        src = source_dir / "fresh.txt"
        src.write_text("fresh")
        mgr.backup_file(str(src))

        mgr.enforce_retention()
        assert len(mgr.snapshot.get_backups()) == 1
        mgr.close()

    def test_mixed_retention(self, vault, source_dir):
        mgr = BackupManager(vault_path=vault, retention_hours=48)

        old = source_dir / "old.txt"
        old.write_text("old")
        mgr.snapshot.create_snapshot(
            str(old), reason="old",
            timestamp=datetime.now() - timedelta(hours=50),
        )

        fresh = source_dir / "fresh.txt"
        fresh.write_text("fresh")
        mgr.backup_file(str(fresh))

        mgr.enforce_retention()
        remaining = mgr.snapshot.get_backups()
        assert len(remaining) == 1
        assert remaining[0]["original_path"] == str(fresh)
        mgr.close()


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------

class TestPerformance:
    def test_backup_latency(self, backup_mgr, source_dir):
        src = source_dir / "perf.txt"
        src.write_text("x" * 10000)

        start = time.time()
        for _ in range(50):
            backup_mgr.backup_file(str(src), reason="perf")
        elapsed = time.time() - start
        # 50 backups should complete well under 5 seconds
        assert elapsed < 5.0

    def test_restore_latency(self, backup_mgr, source_dir):
        src = source_dir / "perf_restore.txt"
        src.write_text("y" * 10000)
        backup_mgr.backup_file(str(src))

        backups = backup_mgr.snapshot.get_backups(original_path=str(src))

        start = time.time()
        for _ in range(50):
            backup_mgr.recovery.restore_file(backups[0]["id"])
        elapsed = time.time() - start
        assert elapsed < 5.0
