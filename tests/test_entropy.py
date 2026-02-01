"""Tests for Phase 2: Entropy Analysis Engine.

Covers:
- Shannon entropy calculation correctness
- Entropy of various file types: .txt, .docx, .pdf, .jpg, .zip
- Encrypted file detection (entropy increase)
- Password-protected ZIP handling
- Performance on large files
- Entropy change detection with baseline tracking
- Cache behaviour
"""

import os
import struct
import time
import zipfile

import pytest

from src.analysis.entropy_analyzer import (
    shannon_entropy,
    calculate_file_entropy,
    _sample_offsets,
    DEFAULT_SAMPLE_SIZE,
    LARGE_FILE_THRESHOLD,
)
from src.analysis.entropy_detector import (
    EntropyBaseline,
    EntropyDetector,
    DEFAULT_DELTA_THRESHOLD,
    HIGH_ENTROPY_ABSOLUTE,
)


# ---------------------------------------------------------------------------
# Shannon entropy unit tests
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_data_returns_zero(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_byte_repeated(self):
        # All identical bytes -> zero entropy
        assert shannon_entropy(b"\x00" * 256) == 0.0

    def test_two_equally_frequent_bytes(self):
        data = b"\x00\x01" * 128
        entropy = shannon_entropy(data)
        assert abs(entropy - 1.0) < 0.01

    def test_uniform_distribution_is_8_bits(self):
        # Every byte value exactly once -> max entropy = 8.0
        data = bytes(range(256))
        entropy = shannon_entropy(data)
        assert abs(entropy - 8.0) < 0.01

    def test_entropy_range(self):
        # Random-ish data should be between 0 and 8
        import random
        random.seed(42)
        data = bytes(random.randint(0, 255) for _ in range(1024))
        entropy = shannon_entropy(data)
        assert 0.0 <= entropy <= 8.0

    def test_low_entropy_text(self):
        data = b"aaaaaabbbbbbcccccc"
        entropy = shannon_entropy(data)
        assert entropy < 2.0


# ---------------------------------------------------------------------------
# File entropy calculation
# ---------------------------------------------------------------------------

class TestCalculateFileEntropy:
    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        assert calculate_file_entropy(str(p)) == 0.0

    def test_nonexistent_file(self):
        assert calculate_file_entropy("/no/such/file.bin") is None

    def test_text_file_low_entropy(self, tmp_path):
        # Plain English text: entropy ~4-5 bits/byte
        text = ("The quick brown fox jumps over the lazy dog. " * 50).encode()
        p = tmp_path / "plain.txt"
        p.write_bytes(text)
        entropy = calculate_file_entropy(str(p))
        assert entropy is not None
        assert 3.0 <= entropy <= 5.5

    def test_only_reads_sample_size(self, tmp_path):
        p = tmp_path / "big.txt"
        p.write_bytes(b"A" * 5000)
        # Entropy of all-A is 0; sample of first 1024 is also all-A
        entropy = calculate_file_entropy(str(p), sample_size=1024)
        assert entropy == 0.0

    def test_respects_custom_sample_size(self, tmp_path):
        data = bytes(range(256)) + b"\x00" * 800
        p = tmp_path / "mixed.bin"
        p.write_bytes(data)
        # Sample only first 256 bytes (uniform) vs first 1024 (padded with zeros)
        ent_256 = calculate_file_entropy(str(p), sample_size=256)
        ent_1024 = calculate_file_entropy(str(p), sample_size=1024)
        assert ent_256 > ent_1024


# ---------------------------------------------------------------------------
# Various file type benchmarks (docs requirement: .txt, .docx, .pdf, .jpg, .zip)
# ---------------------------------------------------------------------------

class TestFileTypeEntropy:
    """Verify entropy ranges for different file types using synthetic content."""

    def test_txt_file(self, tmp_path):
        p = tmp_path / "document.txt"
        p.write_text("Hello world. This is a normal text document.\n" * 100)
        entropy = calculate_file_entropy(str(p))
        # Text files: ~4-5 bits/byte
        assert 3.0 <= entropy <= 5.5

    def test_docx_file_header(self, tmp_path):
        # DOCX files are ZIP archives; the PK header + XML content tends to
        # have moderate-to-high entropy because of compression.
        p = tmp_path / "document.docx"
        zf = zipfile.ZipFile(str(p), "w", zipfile.ZIP_DEFLATED)
        zf.writestr("word/document.xml",
                     "<w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>")
        zf.close()
        entropy = calculate_file_entropy(str(p))
        # Compressed ZIP content: ~5-7
        assert 4.0 <= entropy <= 7.5

    def test_pdf_file_header(self, tmp_path):
        # Minimal PDF structure
        pdf_bytes = (
            b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
            b"xref\n0 4\n0000000000 65535 f \n"
            b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n0\n%%EOF"
        )
        p = tmp_path / "document.pdf"
        p.write_bytes(pdf_bytes)
        entropy = calculate_file_entropy(str(p))
        assert 3.5 <= entropy <= 6.5

    def test_jpg_file_header(self, tmp_path):
        # JFIF header + some fake compressed data
        header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        import random
        random.seed(99)
        body = bytes(random.randint(0, 255) for _ in range(1024))
        p = tmp_path / "photo.jpg"
        p.write_bytes(header + body)
        entropy = calculate_file_entropy(str(p))
        # JPEG data is compressed, should be relatively high
        assert 5.0 <= entropy <= 8.0

    def test_zip_file(self, tmp_path):
        p = tmp_path / "archive.zip"
        with zipfile.ZipFile(str(p), "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.txt", "Some data content here\n" * 200)
        entropy = calculate_file_entropy(str(p))
        # Compressed: ~6-7.5
        assert 4.0 <= entropy <= 8.0

    def test_encrypted_data_high_entropy(self, tmp_path):
        # Simulated encrypted content: uniformly random bytes
        import random
        random.seed(0)
        data = bytes(random.randint(0, 255) for _ in range(DEFAULT_SAMPLE_SIZE))
        p = tmp_path / "encrypted.bin"
        p.write_bytes(data)
        entropy = calculate_file_entropy(str(p))
        assert entropy >= 7.0

    def test_password_protected_zip(self, tmp_path):
        # Python's zipfile can't write encrypted ZIPs, but we can simulate
        # the high-entropy content of one by writing random bytes with a
        # ZIP header (PK signature).
        import random
        random.seed(7)
        body = bytes(random.randint(0, 255) for _ in range(2048))
        p = tmp_path / "protected.zip"
        p.write_bytes(b"PK\x03\x04" + body)
        entropy = calculate_file_entropy(str(p))
        assert entropy >= 7.0


# ---------------------------------------------------------------------------
# Large file sampling / performance
# ---------------------------------------------------------------------------

class TestLargeFileSampling:
    def test_sample_offsets_spacing(self):
        offsets = _sample_offsets(100_000, 1024, 3)
        assert len(offsets) == 3
        assert offsets[0] == 0
        assert offsets[-1] <= 100_000 - 1024

    def test_large_file_uses_multi_sample(self, tmp_path):
        # Create a file just over the threshold
        size = LARGE_FILE_THRESHOLD + 4096
        p = tmp_path / "large.bin"
        with open(str(p), "wb") as f:
            # Write low-entropy at start, high-entropy at end
            f.write(b"\x00" * (size // 2))
            import random
            random.seed(1)
            f.write(bytes(random.randint(0, 255) for _ in range(size // 2)))
            remaining = size - (size // 2) * 2
            if remaining > 0:
                f.write(b"\x00" * remaining)

        entropy = calculate_file_entropy(str(p))
        assert entropy is not None
        # Average of low and high entropy samples
        assert 2.0 <= entropy <= 6.0

    def test_performance_large_file(self, tmp_path):
        size = LARGE_FILE_THRESHOLD + 1024
        p = tmp_path / "perf.bin"
        with open(str(p), "wb") as f:
            f.write(b"\xAB" * size)

        start = time.time()
        calculate_file_entropy(str(p))
        elapsed = time.time() - start
        # Sampling should be fast; well under 1 second
        assert elapsed < 1.0


# ---------------------------------------------------------------------------
# Entropy baseline database
# ---------------------------------------------------------------------------

class TestEntropyBaseline:
    @pytest.fixture
    def baseline(self, tmp_path):
        bl = EntropyBaseline(str(tmp_path / "baselines.db"))
        yield bl
        bl.close()

    def test_set_and_get(self, baseline):
        baseline.set_baseline("/foo/bar.txt", 4.5)
        assert baseline.get_baseline("/foo/bar.txt") == 4.5

    def test_get_missing_returns_none(self, baseline):
        assert baseline.get_baseline("/nonexistent") is None

    def test_update_overwrites(self, baseline):
        baseline.set_baseline("/f.txt", 3.0)
        baseline.set_baseline("/f.txt", 6.0)
        assert baseline.get_baseline("/f.txt") == 6.0

    def test_remove_baseline(self, baseline):
        baseline.set_baseline("/f.txt", 4.0)
        baseline.remove_baseline("/f.txt")
        assert baseline.get_baseline("/f.txt") is None

    def test_log_and_get_alerts(self, baseline):
        baseline.log_alert("/f.txt", 4.0, 7.5, 3.5, True)
        baseline.log_alert("/g.txt", 5.0, 5.5, 0.5, False)
        all_alerts = baseline.get_alerts()
        assert len(all_alerts) == 2
        suspicious = baseline.get_alerts(suspicious_only=True)
        assert len(suspicious) == 1
        assert suspicious[0]["file_path"] == "/f.txt"


# ---------------------------------------------------------------------------
# Entropy detector (change detection)
# ---------------------------------------------------------------------------

class TestEntropyDetector:
    @pytest.fixture
    def detector(self, tmp_path):
        det = EntropyDetector(str(tmp_path / "det.db"))
        yield det
        det.close()

    def test_analyze_normal_text_file(self, detector, tmp_path):
        p = tmp_path / "normal.txt"
        p.write_text("Just some normal text content here.\n" * 50)
        result = detector.analyze_file(str(p))
        assert result is not None
        assert result["suspicious"] is False

    def test_detect_encryption_spike(self, detector, tmp_path):
        p = tmp_path / "victim.txt"
        # Start with low-entropy text
        p.write_text("Normal document content.\n" * 100)
        result1 = detector.analyze_file(str(p))
        assert result1 is not None
        assert result1["suspicious"] is False

        # Simulate encryption: overwrite with random bytes
        import random
        random.seed(42)
        p.write_bytes(bytes(random.randint(0, 255) for _ in range(DEFAULT_SAMPLE_SIZE)))
        result2 = detector.analyze_file(str(p))
        assert result2 is not None
        assert result2["delta"] >= DEFAULT_DELTA_THRESHOLD
        assert result2["suspicious"] is True

    def test_new_encrypted_file_flagged(self, detector, tmp_path):
        import random
        random.seed(0)
        p = tmp_path / "new_encrypted.bin"
        p.write_bytes(bytes(random.randint(0, 255) for _ in range(1024)))
        result = detector.on_file_created(str(p))
        assert result is not None
        assert result["entropy_after"] >= HIGH_ENTROPY_ABSOLUTE
        assert result["suspicious"] is True

    def test_new_normal_file_not_flagged(self, detector, tmp_path):
        p = tmp_path / "readme.txt"
        p.write_text("Hello world.\n" * 100)
        result = detector.on_file_created(str(p))
        assert result is not None
        assert result["suspicious"] is False

    def test_deleted_file_clears_baseline(self, detector, tmp_path):
        p = tmp_path / "temp.txt"
        p.write_text("data")
        detector.on_file_created(str(p))
        assert detector.baseline.get_baseline(str(p)) is not None

        detector.on_file_deleted(str(p))
        assert detector.baseline.get_baseline(str(p)) is None

    def test_cache_is_used(self, detector, tmp_path):
        p = tmp_path / "cached.txt"
        p.write_text("original content\n" * 50)
        detector.analyze_file(str(p))
        # Value should be in the in-memory cache
        assert str(p) in detector._cache

    def test_gradual_increase_below_threshold(self, detector, tmp_path):
        p = tmp_path / "slow.txt"
        p.write_text("a" * 500 + "b" * 500)
        detector.analyze_file(str(p))

        # Small increase, below threshold
        p.write_text("a" * 300 + "b" * 300 + "c" * 200 + "d" * 200)
        result = detector.analyze_file(str(p))
        assert result["suspicious"] is False

    def test_nonexistent_file_returns_none(self, detector):
        assert detector.analyze_file("/no/such/file") is None

    def test_alerts_persisted(self, detector, tmp_path):
        import random
        random.seed(42)
        p = tmp_path / "alert_test.txt"
        p.write_text("Normal.\n" * 100)
        detector.analyze_file(str(p))
        p.write_bytes(bytes(random.randint(0, 255) for _ in range(1024)))
        detector.analyze_file(str(p))

        alerts = detector.baseline.get_alerts(suspicious_only=True)
        assert len(alerts) >= 1
