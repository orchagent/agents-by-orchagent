"""Tests for file scanner."""

import tempfile
from pathlib import Path

import pytest

from leak_finder.scanner import scan_file, scan_directory, redact_secret


class TestRedactSecret:
    """Test secret redaction."""

    def test_redact_long_secret(self):
        """Test redacting a long secret."""
        result = redact_secret("AKIAIOSFODNN7EXAMPLE")
        assert result == "AKIA************MPLE"
        assert result.startswith("AKIA")
        assert result.endswith("MPLE")

    def test_redact_short_secret(self):
        """Test redacting a short secret."""
        result = redact_secret("short")
        assert result == "*****"

    def test_redact_exactly_8_chars(self):
        """Test redacting exactly 8 character secret."""
        result = redact_secret("12345678")
        assert result == "********"


class TestScanFile:
    """Test file scanning."""

    def test_scan_file_with_aws_key(self):
        """Test scanning a file with a fake AWS key."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
            f.write("# Normal code here\n")
            f.flush()

            findings = scan_file(f.name)

            assert len(findings) >= 1
            aws_finding = next((f for f in findings if f.type == "aws_access_key_id"), None)
            assert aws_finding is not None
            assert aws_finding.severity == "critical"
            assert aws_finding.line == 1
            assert "AKIA" in aws_finding.preview
            assert "MPLE" in aws_finding.preview

        Path(f.name).unlink()

    def test_scan_file_with_stripe_key(self):
        """Test scanning a file with Stripe keys."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write('const STRIPE_KEY = "sk_live_1234567890abcdefghijklmnop";\n')
            f.flush()

            findings = scan_file(f.name)

            assert len(findings) >= 1
            stripe_finding = next((f for f in findings if f.type == "stripe_live_key"), None)
            assert stripe_finding is not None
            assert stripe_finding.severity == "critical"

        Path(f.name).unlink()

    def test_scan_file_with_private_key(self):
        """Test scanning a file with a private key."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\n")
            f.write("MIIEpAIBAAKCAQEA...\n")
            f.write("-----END RSA PRIVATE KEY-----\n")
            f.flush()

            findings = scan_file(f.name)

            assert len(findings) >= 1
            key_finding = next((f for f in findings if f.type == "private_key_rsa"), None)
            assert key_finding is not None
            assert key_finding.severity == "critical"

        Path(f.name).unlink()

    def test_scan_file_no_secrets(self):
        """Test scanning a clean file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("# Just a normal Python file\n")
            f.write("def hello():\n")
            f.write('    print("Hello, World!")\n')
            f.flush()

            findings = scan_file(f.name)
            assert len(findings) == 0

        Path(f.name).unlink()

    def test_scan_nonexistent_file(self):
        """Test scanning a file that doesn't exist."""
        findings = scan_file("/nonexistent/file.py")
        assert findings == []


class TestScanDirectory:
    """Test directory scanning."""

    def test_scan_directory_with_secrets(self):
        """Test scanning a directory with secrets."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create a file with a secret
            secret_file = temp_path / "config.py"
            secret_file.write_text('API_KEY = "sk_live_1234567890abcdefghijklmnop"\n')

            # Create a clean file
            clean_file = temp_path / "main.py"
            clean_file.write_text("print('hello')\n")

            findings = scan_directory(temp_path)

            assert len(findings) >= 1
            assert any(f.file == "config.py" for f in findings)

    def test_scan_directory_skips_node_modules(self):
        """Test that node_modules is skipped."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create node_modules with a secret
            node_modules = temp_path / "node_modules" / "package"
            node_modules.mkdir(parents=True)
            secret_file = node_modules / "config.js"
            secret_file.write_text('const key = "sk_live_1234567890abcdefghijklmnop";\n')

            # Create a file outside node_modules
            clean_file = temp_path / "main.js"
            clean_file.write_text("console.log('hello');\n")

            findings = scan_directory(temp_path)

            # Should not find the secret in node_modules
            assert not any("node_modules" in f.file for f in findings)

    def test_scan_directory_nonexistent(self):
        """Test scanning a directory that doesn't exist."""
        findings = scan_directory("/nonexistent/directory")
        assert findings == []
