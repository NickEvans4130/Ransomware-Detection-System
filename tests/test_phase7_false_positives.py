"""Phase 7: False Positive Testing.

Simulates legitimate software behaviors as listed in docs:
    - Microsoft Word (document editing)
    - 7-Zip (batch compression)
    - Backup software (Acronis, Windows Backup)
    - Antivirus scans
    - Windows Update
    - Photo editing software

Verifies that none of these legitimate patterns trigger CRITICAL detection
or cause automated response actions (quarantine/terminate).

Threshold tuning: these tests confirm that the scoring weights and
thresholds correctly differentiate ransomware from legitimate activity.
"""

import os
import time

import pytest

from src.analysis.behavior_analyzer import BehaviorAnalyzer
from src.analysis.pattern_detector import PatternDetector, FileEvent
from src.analysis.threat_scoring import (
    calculate_threat_score,
    LEVEL_NORMAL,
    LEVEL_SUSPICIOUS,
    LEVEL_LIKELY,
    LEVEL_CRITICAL,
)
from src.response.backup_manager import BackupManager
from src.response.response_engine import ResponseEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def analyzer():
    """Standard behavior analyzer with production thresholds."""
    return BehaviorAnalyzer(
        time_window=60,
        mass_modify_threshold=20,
        entropy_spike_threshold=2.0,
        entropy_spike_min_files=3,
        extension_change_min_files=3,
        directory_traversal_min_dirs=4,
    )


@pytest.fixture
def response_system(tmp_path):
    """Full response system to verify no quarantine is triggered."""
    bm = BackupManager(str(tmp_path / "vault"))
    responses = []
    re = ResponseEngine(bm, safe_mode=False, enable_desktop_alerts=False)
    ba = BehaviorAnalyzer(
        time_window=60,
        mass_modify_threshold=20,
        entropy_spike_threshold=2.0,
        entropy_spike_min_files=3,
        extension_change_min_files=3,
        directory_traversal_min_dirs=4,
        on_threat=lambda ts: responses.append(re.respond(ts)),
    )
    yield {"analyzer": ba, "engine": re, "responses": responses}
    bm.close()


# ---------------------------------------------------------------------------
# 1. Microsoft Word - Document Editing
# ---------------------------------------------------------------------------

class TestWordEditing:
    """Microsoft Word edits one file at a time, creates temp files,
    and operates in the same directory. Entropy stays within normal
    range for document files (~4-6 bits/byte)."""

    def test_single_document_edit(self, analyzer):
        """Editing a single document should be NORMAL."""
        for i in range(5):
            analyzer.process_event(
                event_type="modified",
                file_path="/home/user/Documents/report.docx",
                process_id=100,
                process_name="WINWORD.EXE",
                entropy_delta=0.3,
            )
        score = analyzer.get_score(100)
        assert score.level == LEVEL_NORMAL
        assert score.action_required is False

    def test_word_temp_file_creation(self, analyzer):
        """Word creates ~WRL*.tmp temp files alongside the document."""
        analyzer.process_event(
            event_type="created",
            file_path="/home/user/Documents/~WRL0001.tmp",
            process_id=100,
            process_name="WINWORD.EXE",
        )
        analyzer.process_event(
            event_type="modified",
            file_path="/home/user/Documents/report.docx",
            process_id=100,
            process_name="WINWORD.EXE",
            entropy_delta=0.2,
        )
        analyzer.process_event(
            event_type="deleted",
            file_path="/home/user/Documents/~WRL0001.tmp",
            process_id=100,
            process_name="WINWORD.EXE",
        )
        score = analyzer.get_score(100)
        assert score.level == LEVEL_NORMAL

    def test_multiple_documents_open(self, analyzer):
        """Editing several documents in different directories."""
        docs = [
            "/home/user/Documents/report.docx",
            "/home/user/Documents/thesis.docx",
            "/home/user/Desktop/notes.docx",
        ]
        for doc in docs:
            for _ in range(3):
                analyzer.process_event(
                    event_type="modified",
                    file_path=doc,
                    process_id=100,
                    process_name="WINWORD.EXE",
                    entropy_delta=0.1,
                )
        score = analyzer.get_score(100)
        assert score.action_required is False

    def test_word_autosave(self, analyzer):
        """Frequent autosaves should not trigger mass modification."""
        for i in range(15):
            analyzer.process_event(
                event_type="modified",
                file_path="/home/user/Documents/report.docx",
                process_id=100,
                process_name="WINWORD.EXE",
                entropy_delta=0.05,
            )
        score = analyzer.get_score(100)
        assert score.level == LEVEL_NORMAL


# ---------------------------------------------------------------------------
# 2. 7-Zip - Batch Compression
# ---------------------------------------------------------------------------

class TestSevenZipCompression:
    """7-Zip creates compressed archives. Compressed files have high entropy
    (~6-7 bits/byte) but the pattern differs from ransomware: 7-Zip writes
    a single output file, not many files across directories."""

    def test_single_archive_creation(self, analyzer):
        """Creating a single .7z archive should be NORMAL."""
        analyzer.process_event(
            event_type="created",
            file_path="/home/user/Documents/backup.7z",
            process_id=200,
            process_name="7z",
        )
        # Single large write to the archive
        for _ in range(5):
            analyzer.process_event(
                event_type="modified",
                file_path="/home/user/Documents/backup.7z",
                process_id=200,
                process_name="7z",
                entropy_delta=0.1,
            )
        score = analyzer.get_score(200)
        assert score.level == LEVEL_NORMAL
        assert score.action_required is False

    def test_batch_extraction(self, analyzer):
        """Extracting many files from an archive creates multiple files
        but they have normal entropy."""
        for i in range(15):
            analyzer.process_event(
                event_type="created",
                file_path=f"/home/user/extracted/file{i}.txt",
                process_id=200,
                process_name="7z",
            )
        score = analyzer.get_score(200)
        assert score.action_required is False

    def test_compress_multiple_dirs(self, analyzer):
        """Compressing files from multiple dirs -- reads many, writes one."""
        # 7-Zip reads from multiple dirs but writes to one archive
        analyzer.process_event(
            event_type="created",
            file_path="/home/user/archive.7z",
            process_id=200,
            process_name="7z",
        )
        for i in range(8):
            analyzer.process_event(
                event_type="modified",
                file_path="/home/user/archive.7z",
                process_id=200,
                process_name="7z",
                entropy_delta=0.05,
            )
        score = analyzer.get_score(200)
        assert score.level == LEVEL_NORMAL


# ---------------------------------------------------------------------------
# 3. Backup Software (Acronis, Windows Backup)
# ---------------------------------------------------------------------------

class TestBackupSoftware:
    """Backup software copies many files but does not modify originals,
    does not rename extensions to suspicious ones, and operates from
    a system path (not temp dirs)."""

    def test_bulk_file_copy(self, analyzer):
        """Copying files to a backup destination -- creates many files."""
        for i in range(18):
            analyzer.process_event(
                event_type="created",
                file_path=f"/mnt/backup/daily/file{i}.bak",
                process_id=300,
                process_name="AcronisBackup",
            )
        score = analyzer.get_score(300)
        assert score.action_required is False

    def test_backup_with_moderate_traversal(self, analyzer):
        """Backup traverses many directories but uses .bak extension."""
        for i in range(6):
            analyzer.process_event(
                event_type="created",
                file_path=f"/mnt/backup/dir{i}/file.bak",
                process_id=300,
                process_name="AcronisBackup",
            )
        score = analyzer.get_score(300)
        # May trigger directory_traversal (10 pts) but that alone is NORMAL
        assert score.level == LEVEL_NORMAL

    def test_windows_backup_vhd_creation(self, analyzer):
        """Windows Backup creates a single large .vhd file."""
        for _ in range(10):
            analyzer.process_event(
                event_type="modified",
                file_path="/mnt/backup/SystemImage.vhd",
                process_id=300,
                process_name="wbengine",
                entropy_delta=0.2,
            )
        score = analyzer.get_score(300)
        assert score.level == LEVEL_NORMAL


# ---------------------------------------------------------------------------
# 4. Antivirus Scans
# ---------------------------------------------------------------------------

class TestAntivirusScan:
    """Antivirus reads files across many directories but does not modify
    them. File events from AV are primarily reads (no modification events
    in our monitor). The only events might be quarantine moves to a safe
    location."""

    def test_scan_no_modifications(self, analyzer):
        """AV scanning directories should produce no modification events.
        Even if some file metadata events fire, entropy stays unchanged."""
        # An AV scan typically doesn't trigger filesystem write events.
        # But if it does (metadata access), they should be benign.
        for i in range(5):
            analyzer.process_event(
                event_type="modified",
                file_path=f"/home/user/dir{i}/scan_target.exe",
                process_id=400,
                process_name="clamd",
                entropy_delta=0.0,
            )
        score = analyzer.get_score(400)
        assert score.level == LEVEL_NORMAL

    def test_av_quarantine_move(self, analyzer):
        """AV moving a single file to quarantine."""
        analyzer.process_event(
            event_type="moved",
            file_path="/var/quarantine/malware.exe",
            old_path="/home/user/Downloads/malware.exe",
            process_id=400,
            process_name="clamd",
        )
        score = analyzer.get_score(400)
        assert score.action_required is False

    def test_av_update_signatures(self, analyzer):
        """AV updating signature database -- single file modified."""
        for _ in range(3):
            analyzer.process_event(
                event_type="modified",
                file_path="/var/lib/clamav/daily.cvd",
                process_id=400,
                process_name="freshclam",
                entropy_delta=0.5,
            )
        score = analyzer.get_score(400)
        assert score.level == LEVEL_NORMAL


# ---------------------------------------------------------------------------
# 5. Windows Update / System Updates
# ---------------------------------------------------------------------------

class TestSystemUpdates:
    """OS updates modify system files across multiple directories. While
    they touch many files, they don't exhibit entropy spikes or suspicious
    extension changes."""

    def test_package_manager_updates(self, analyzer):
        """Package manager installing updates -- modifies system files."""
        system_files = [
            "/usr/lib/libssl.so",
            "/usr/lib/libcrypto.so",
            "/usr/bin/openssl",
            "/usr/share/doc/openssl/changelog",
        ]
        for f in system_files:
            analyzer.process_event(
                event_type="modified",
                file_path=f,
                process_id=500,
                process_name="dpkg",
                entropy_delta=0.1,
            )
        score = analyzer.get_score(500)
        assert score.level == LEVEL_NORMAL

    def test_large_update_batch(self, analyzer):
        """Large update installing many files across /usr."""
        for i in range(15):
            analyzer.process_event(
                event_type="modified",
                file_path=f"/usr/lib/update{i}.so",
                process_id=500,
                process_name="apt",
                entropy_delta=0.05,
            )
        score = analyzer.get_score(500)
        assert score.action_required is False

    def test_update_with_new_files(self, analyzer):
        """Update creating new files -- not suspicious extensions."""
        for i in range(10):
            analyzer.process_event(
                event_type="created",
                file_path=f"/usr/share/locale/en/LC_{i}.mo",
                process_id=500,
                process_name="apt",
            )
        score = analyzer.get_score(500)
        assert score.level == LEVEL_NORMAL


# ---------------------------------------------------------------------------
# 6. Photo Editing Software
# ---------------------------------------------------------------------------

class TestPhotoEditing:
    """Photo editors like GIMP/Photoshop modify a few files intensively.
    Image files have moderate entropy. The pattern is: few files, same
    directory, no extension changes, no mass modification."""

    def test_single_image_edit(self, analyzer):
        """Editing a single image repeatedly."""
        for i in range(10):
            analyzer.process_event(
                event_type="modified",
                file_path="/home/user/Photos/vacation.psd",
                process_id=600,
                process_name="gimp",
                entropy_delta=0.2,
            )
        score = analyzer.get_score(600)
        assert score.level == LEVEL_NORMAL

    def test_batch_photo_export(self, analyzer):
        """Exporting multiple photos -- creates files in one directory."""
        for i in range(15):
            analyzer.process_event(
                event_type="created",
                file_path=f"/home/user/Photos/export/photo{i}.jpg",
                process_id=600,
                process_name="gimp",
            )
        score = analyzer.get_score(600)
        assert score.action_required is False

    def test_photo_with_sidecar_files(self, analyzer):
        """RAW editors create sidecar .xmp files alongside originals."""
        for i in range(5):
            analyzer.process_event(
                event_type="modified",
                file_path=f"/home/user/Photos/raw/IMG_{i}.CR2",
                process_id=600,
                process_name="darktable",
                entropy_delta=0.1,
            )
            analyzer.process_event(
                event_type="created",
                file_path=f"/home/user/Photos/raw/IMG_{i}.CR2.xmp",
                process_id=600,
                process_name="darktable",
            )
        score = analyzer.get_score(600)
        assert score.level == LEVEL_NORMAL


# ---------------------------------------------------------------------------
# Threshold Validation
# ---------------------------------------------------------------------------

class TestThresholdTuning:
    """Verify the scoring system correctly separates ransomware from
    legitimate activity at the documented thresholds."""

    def test_single_indicator_not_critical(self, analyzer):
        """Any single indicator alone should not reach CRITICAL (71+)."""
        # Highest single weight is entropy_spike at 30
        for i in range(5):
            analyzer.process_event(
                event_type="modified",
                file_path=f"/data/f{i}.txt",
                process_id=700,
                process_name="test",
                entropy_delta=3.0,
            )
        score = analyzer.get_score(700)
        assert score.score <= 30
        assert score.action_required is False

    def test_two_indicators_still_below_critical(self, analyzer):
        """Two indicators should typically stay below CRITICAL."""
        # mass_modification (25) + directory_traversal (10) = 35
        for i in range(25):
            analyzer.process_event(
                event_type="modified",
                file_path=f"/dir{i}/f{i}.txt",
                process_id=701,
                process_name="test",
            )
        score = analyzer.get_score(701)
        assert score.score <= 35
        assert score.action_required is False

    def test_three_strong_indicators_reach_critical(self, analyzer):
        """Three strong indicators should cross CRITICAL threshold."""
        # mass_modification (25) + entropy_spike (30) +
        # extension_manipulation (25) = 80
        for i in range(25):
            analyzer.process_event(
                event_type="modified",
                file_path=f"/data/f{i}.txt",
                process_id=702,
                process_name="ransom",
                entropy_delta=3.0,
            )
        for i in range(5):
            analyzer.process_event(
                event_type="extension_changed",
                file_path=f"/data/f{i}.locked",
                file_extension=".locked",
                old_path=f"/data/f{i}.txt",
                process_id=702,
                process_name="ransom",
            )
        score = analyzer.get_score(702)
        assert score.score >= 71
        assert score.action_required is True

    def test_no_false_positive_response_actions(self, response_system):
        """Legitimate patterns should never trigger quarantine responses."""
        ba = response_system["analyzer"]
        responses = response_system["responses"]

        # Simulate all legitimate patterns from above
        patterns = [
            # Word editing
            ("modified", "/home/user/doc.docx", 100, "word", 0.2),
            # 7-Zip
            ("created", "/home/user/archive.7z", 200, "7z", 0.0),
            # Backup
            ("created", "/mnt/backup/file.bak", 300, "backup", 0.0),
            # AV scan
            ("modified", "/usr/lib/av.dat", 400, "clamd", 0.0),
            # System update
            ("modified", "/usr/lib/libssl.so", 500, "apt", 0.1),
            # Photo editing
            ("modified", "/home/user/photo.psd", 600, "gimp", 0.2),
        ]

        for etype, path, pid, pname, delta in patterns:
            for i in range(10):
                ba.process_event(
                    event_type=etype,
                    file_path=path.replace(".", f"{i}.") if i > 0 else path,
                    process_id=pid,
                    process_name=pname,
                    entropy_delta=delta,
                )

        # No responses should have been triggered via on_threat callback
        assert len(responses) == 0

        # All scores should be below action threshold
        for pid in [100, 200, 300, 400, 500, 600]:
            score = ba.get_score(pid)
            assert score is not None
            assert score.action_required is False, \
                f"False positive for pid {pid} ({score.process_name}): " \
                f"score={score.score}, level={score.level}"
