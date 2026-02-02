"""Phase 7: Safe Simulated Ransomware Testing.

DO NOT USE ON REAL DATA -- TESTING ONLY.

Simulates ransomware behavior in an isolated temp directory and verifies:
    1. Detection occurs (behavior analyzer flags CRITICAL)
    2. Process is quarantined (response engine acts)
    3. Files can be recovered (backup + restore pipeline)

Based on the example code from docs/PHASE7_TESTING.md.
"""

import os
import time

import pytest
from cryptography.fernet import Fernet

from src.analysis.behavior_analyzer import BehaviorAnalyzer
from src.analysis.entropy_analyzer import calculate_file_entropy
from src.analysis.entropy_detector import EntropyDetector
from src.response.backup_manager import BackupManager
from src.response.response_engine import ResponseEngine
from src.response.recovery_workflow import RecoveryWorkflow


# ---------------------------------------------------------------------------
# Safe test ransomware (from docs)
# ---------------------------------------------------------------------------

def simulate_ransomware(test_dir: str) -> list[str]:
    """Encrypt files in test directory rapidly to simulate ransomware behavior.

    Returns list of encrypted file paths.

    DO NOT USE ON REAL DATA -- TESTING ONLY.
    """
    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted_files = []

    for root, dirs, files in os.walk(test_dir):
        for file in files:
            filepath = os.path.join(root, file)
            # Read, encrypt, write back
            with open(filepath, "rb") as f:
                data = f.read()
            encrypted = cipher.encrypt(data)
            with open(filepath, "wb") as f:
                f.write(encrypted)
            # Rename with .encrypted extension
            new_path = filepath + ".encrypted"
            os.rename(filepath, new_path)
            encrypted_files.append(new_path)

    return encrypted_files


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sandbox(tmp_path):
    """Isolated test environment with pre-created files and all services."""
    # Create test files
    test_dir = tmp_path / "target"
    test_dir.mkdir()
    for sub in ["docs", "photos", "projects"]:
        d = test_dir / sub
        d.mkdir()

    original_content = {}
    file_num = 0
    for sub in ["docs", "photos", "projects"]:
        for i in range(5):
            f = test_dir / sub / f"file{i}.txt"
            content = f"Original content in {sub}/file{i}.txt -- data block {file_num}"
            f.write_text(content)
            original_content[str(f)] = content
            file_num += 1

    # Set up services
    vault = str(tmp_path / "vault")
    ent_db = str(tmp_path / "ent.db")

    bm = BackupManager(vault)
    entropy = EntropyDetector(ent_db)

    responses_triggered = []
    re = ResponseEngine(bm, safe_mode=False, enable_desktop_alerts=False)

    ba = BehaviorAnalyzer(
        time_window=60,
        mass_modify_threshold=5,
        entropy_spike_min_files=2,
        on_threat=lambda ts: responses_triggered.append(re.respond(ts)),
    )

    yield {
        "test_dir": test_dir,
        "original_content": original_content,
        "backup_manager": bm,
        "entropy_detector": entropy,
        "response_engine": re,
        "behavior_analyzer": ba,
        "responses": responses_triggered,
        "tmp_path": tmp_path,
    }

    bm.close()
    entropy.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSimulatedRansomware:
    def test_ransomware_encrypts_files(self, sandbox):
        """Verify the simulation actually modifies files."""
        test_dir = sandbox["test_dir"]
        originals = sandbox["original_content"]

        encrypted = simulate_ransomware(str(test_dir))
        assert len(encrypted) == 15  # 3 dirs * 5 files

        # All original files should be gone (renamed with .encrypted)
        for orig_path in originals:
            assert not os.path.exists(orig_path)

        # Encrypted files should exist and differ from originals
        for enc_path in encrypted:
            assert os.path.exists(enc_path)
            with open(enc_path, "rb") as f:
                data = f.read()
            # Fernet ciphertext starts with 'gAAAAA'
            assert data[:5] == b"gAAAA"

    def test_entropy_increase_on_encryption(self, sandbox):
        """Encrypted files should have higher entropy than text originals."""
        test_dir = sandbox["test_dir"]
        originals = sandbox["original_content"]

        # Measure original entropy
        original_entropies = {}
        for path in originals:
            ent = calculate_file_entropy(path)
            if ent is not None:
                original_entropies[path] = ent

        # Run encryption
        encrypted = simulate_ransomware(str(test_dir))

        # Measure encrypted entropy
        for enc_path in encrypted:
            ent = calculate_file_entropy(enc_path)
            assert ent is not None
            assert ent > 5.0  # Encrypted data has high entropy

        # Original text had lower entropy
        for ent in original_entropies.values():
            assert ent < 6.0

    def test_detection_within_timeframe(self, sandbox):
        """Simulated ransomware should be detected by behavior analyzer."""
        ba = sandbox["behavior_analyzer"]
        entropy_det = sandbox["entropy_detector"]
        test_dir = sandbox["test_dir"]
        originals = sandbox["original_content"]

        # Step 1: Establish baselines for all files
        for path in originals:
            entropy_det.on_file_created(path)

        # Step 2: Simulate ransomware -- feed events to behavior analyzer
        start = time.time()

        # Simulate the modification events the monitor would generate
        pid = 6666
        proc_name = "ransomware_sim"

        for path in originals:
            # In a real attack the file would be encrypted before the
            # monitor sees it, producing a large entropy delta.  We
            # simulate the delta that Fernet encryption would cause
            # (text ~4 bits/byte -> ciphertext ~7.9 bits/byte = delta ~3.9).
            ba.process_event(
                event_type="modified",
                file_path=path,
                process_id=pid,
                process_name=proc_name,
                entropy_delta=3.9,
            )

        # Now simulate the extension change events
        for path in originals:
            ba.process_event(
                event_type="extension_changed",
                file_path=path + ".encrypted",
                file_extension=".encrypted",
                old_path=path,
                process_id=pid,
                process_name=proc_name,
            )

        # Simulate deletion of originals
        for path in originals:
            ba.process_event(
                event_type="deleted",
                file_path=path,
                process_id=pid,
                process_name=proc_name,
            )

        elapsed = time.time() - start

        # Detection should be fast
        assert elapsed < 2.0, f"Detection took {elapsed:.2f}s, expected <2s"

        # Should have reached CRITICAL
        score = ba.get_score(pid)
        assert score is not None
        assert score.action_required is True
        assert score.score >= 71

    def test_quarantine_triggered(self, sandbox):
        """Response engine should attempt to quarantine the process."""
        ba = sandbox["behavior_analyzer"]
        re = sandbox["response_engine"]
        responses = sandbox["responses"]

        pid = 7777
        proc_name = "ransomware_sim"

        # Generate enough suspicious events to trigger CRITICAL
        for i in range(10):
            ba.process_event(
                event_type="modified",
                file_path=f"/tmp/dir{i}/file{i}.txt",
                process_id=pid,
                process_name=proc_name,
                entropy_delta=4.0,
            )

        for i in range(5):
            ba.process_event(
                event_type="extension_changed",
                file_path=f"/tmp/dir{i}/file{i}.encrypted",
                file_extension=".encrypted",
                old_path=f"/tmp/dir{i}/file{i}.txt",
                process_id=pid,
                process_name=proc_name,
            )

        # Response should have been triggered via callback
        assert len(responses) > 0
        last_response = responses[-1]
        assert last_response.escalation_level >= 3

        # Process suspension should have been attempted
        suspend_actions = [a for a in last_response.process_actions
                          if a.action == "suspend"]
        assert len(suspend_actions) >= 1

    def test_files_recoverable_after_attack(self, sandbox):
        """Files backed up before the attack can be fully restored."""
        bm = sandbox["backup_manager"]
        test_dir = sandbox["test_dir"]
        originals = sandbox["original_content"]

        # Step 1: Back up all files (simulating Level 2 backup response)
        for path, content in originals.items():
            bm.backup_file(path, process_name="ransomware_sim")

        # Step 2: Run simulated ransomware
        simulate_ransomware(str(test_dir))

        # Step 3: Verify originals are gone
        for path in originals:
            assert not os.path.exists(path)

        # Step 4: Restore all files backed up for this process
        results = bm.recovery.restore_by_process("ransomware_sim")
        succeeded = sum(1 for r in results if r.success)
        assert succeeded == 15  # all 15 files

        # Step 5: Verify content matches originals
        for path, content in originals.items():
            assert os.path.exists(path)
            assert open(path).read() == content

    def test_full_attack_simulation(self, sandbox):
        """Complete end-to-end: backup -> detect -> quarantine -> restore."""
        ba = sandbox["behavior_analyzer"]
        bm = sandbox["backup_manager"]
        re = sandbox["response_engine"]
        entropy_det = sandbox["entropy_detector"]
        test_dir = sandbox["test_dir"]
        originals = sandbox["original_content"]

        # 1. Pre-attack: backup files and establish baselines
        for path in originals:
            bm.backup_file(path, process_name="attacker")
            entropy_det.on_file_created(path)

        # 2. Simulate ransomware encrypting files
        simulate_ransomware(str(test_dir))

        # 3. Feed detection events for each encrypted file
        pid = 8888
        for path in originals:
            ba.process_event(
                event_type="modified",
                file_path=path,
                process_id=pid,
                process_name="attacker",
                entropy_delta=4.0,
            )
            ba.process_event(
                event_type="extension_changed",
                file_path=path + ".encrypted",
                file_extension=".encrypted",
                old_path=path,
                process_id=pid,
                process_name="attacker",
            )

        # 4. Verify CRITICAL detection
        score = ba.get_score(pid)
        assert score is not None
        assert score.action_required is True

        # 5. Verify response was triggered (via on_threat callback)
        responses = sandbox["responses"]
        assert len(responses) > 0

        # 6. Restore all files
        results = bm.recovery.restore_by_process("attacker")
        succeeded = sum(1 for r in results if r.success)
        assert succeeded == 15

        # 7. Verify recovery
        for path, content in originals.items():
            assert os.path.exists(path)
            assert open(path).read() == content

        # 8. Generate incident report
        wf = RecoveryWorkflow(bm)
        report = wf.create_incident_report(
            process_id=pid,
            process_name="attacker",
            threat_score=score.score,
            triggered_indicators=score.triggered_indicators,
            actions_taken=["terminated", "blocked", "files restored"],
            restore_results=results,
        )
        assert report.threat_score >= 71
        assert len(report.affected_files) == 15


class TestRansomwareIndicators:
    """Verify each indicator is triggered by ransomware-like behavior."""

    def test_mass_modification_triggered(self, sandbox):
        ba = sandbox["behavior_analyzer"]
        for i in range(10):
            ba.process_event(
                event_type="modified",
                file_path=f"/data/f{i}.txt",
                process_id=900,
                process_name="ransom",
            )
        score = ba.get_score(900)
        assert "mass_modification" in score.triggered_indicators

    def test_entropy_spike_triggered(self, sandbox):
        ba = sandbox["behavior_analyzer"]
        for i in range(5):
            ba.process_event(
                event_type="modified",
                file_path=f"/data/f{i}.txt",
                process_id=901,
                process_name="ransom",
                entropy_delta=4.0,
            )
        score = ba.get_score(901)
        assert "entropy_spike" in score.triggered_indicators

    def test_extension_manipulation_triggered(self, sandbox):
        ba = sandbox["behavior_analyzer"]
        for i in range(5):
            ba.process_event(
                event_type="extension_changed",
                file_path=f"/data/f{i}.locked",
                file_extension=".locked",
                old_path=f"/data/f{i}.txt",
                process_id=902,
                process_name="ransom",
            )
        score = ba.get_score(902)
        assert "extension_manipulation" in score.triggered_indicators

    def test_directory_traversal_triggered(self, sandbox):
        ba = sandbox["behavior_analyzer"]
        for i in range(5):
            ba.process_event(
                event_type="modified",
                file_path=f"/dir{i}/f.txt",
                process_id=903,
                process_name="ransom",
            )
        score = ba.get_score(903)
        assert "directory_traversal" in score.triggered_indicators

    def test_deletion_pattern_triggered(self, sandbox):
        ba = sandbox["behavior_analyzer"]
        for i in range(3):
            ba.process_event(
                event_type="deleted",
                file_path=f"/data/doc{i}.txt",
                process_id=904,
                process_name="ransom",
            )
            ba.process_event(
                event_type="created",
                file_path=f"/data/doc{i}.encrypted",
                file_extension=".encrypted",
                process_id=904,
                process_name="ransom",
            )
        score = ba.get_score(904)
        assert "deletion_pattern" in score.triggered_indicators
