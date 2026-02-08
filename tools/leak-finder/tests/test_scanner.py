"""Tests for file scanner."""

import tempfile
from pathlib import Path

import pytest

from leak_finder.scanner import (
    scan_file,
    scan_directory,
    redact_secret,
    is_code_declaration,
    is_low_entropy_value,
    SKIP_DIRS,
)


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


class TestSkipDirs:
    """Test that all expected directories are in SKIP_DIRS."""

    @pytest.mark.parametrize(
        "dir_name",
        [
            "node_modules",
            ".git",
            "venv",
            ".venv",
            "Pods",
            "bower_components",
            ".gradle",
            ".cargo",
            "DerivedData",
            ".bundle",
            ".tox",
            ".eggs",
            "vendor",
            "target",
            "dist",
            "build",
        ],
    )
    def test_skip_dir_present(self, dir_name):
        """Test that expected directory is in SKIP_DIRS."""
        assert dir_name in SKIP_DIRS

    @pytest.mark.parametrize(
        "dir_name",
        ["Pods", "bower_components", ".gradle", ".cargo", "DerivedData", ".bundle", ".tox", ".eggs"],
    )
    def test_vendor_dirs_skipped_during_scan(self, dir_name):
        """Test that vendor directories are actually skipped during scanning."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create vendor dir with a secret
            vendor_dir = temp_path / dir_name / "some_package"
            vendor_dir.mkdir(parents=True)
            secret_file = vendor_dir / "config.py"
            secret_file.write_text('secret = "sk_live_1234567890abcdefghijklmnop"\n')

            findings = scan_directory(temp_path)

            assert not any(dir_name in f.file for f in findings)


class TestExtraSkipDirs:
    """Test the extra_skip_dirs parameter."""

    def test_extra_skip_dirs_excludes_directory(self):
        """Test that extra_skip_dirs causes additional dirs to be skipped."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create a custom dir with a secret
            custom_dir = temp_path / "my-generated-code"
            custom_dir.mkdir()
            secret_file = custom_dir / "config.py"
            secret_file.write_text('secret = "sk_live_1234567890abcdefghijklmnop"\n')

            # Create a normal file with a secret (should still be found)
            normal_file = temp_path / "app.py"
            normal_file.write_text('key = "sk_live_1234567890abcdefghijklmnop"\n')

            findings = scan_directory(temp_path, extra_skip_dirs={"my-generated-code"})

            # Should find the secret in app.py but not in my-generated-code
            assert any(f.file == "app.py" for f in findings)
            assert not any("my-generated-code" in f.file for f in findings)

    def test_no_extra_skip_dirs_includes_directory(self):
        """Test that without extra_skip_dirs the directory IS scanned."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            custom_dir = temp_path / "my-generated-code"
            custom_dir.mkdir()
            secret_file = custom_dir / "config.py"
            secret_file.write_text('secret = "sk_live_1234567890abcdefghijklmnop"\n')

            findings = scan_directory(temp_path)

            assert any("my-generated-code" in f.file for f in findings)


class TestCodeDeclarationDetection:
    """Test is_code_declaration() for generic pattern FP reduction."""

    @pytest.mark.parametrize(
        "line,expected",
        [
            # Type annotations — should be detected
            ("    password: str", True),
            ("    secret: String", True),
            ("    api_key?: string", True),
            ("    password: Optional[str]", True),
            # Property declarations
            ("NSString *password;", True),
            ("var password String", True),
            # Self-assignment
            ("self.password = password", True),
            # Env var references
            ('password = os.environ["PASSWORD"]', True),
            ('secret = os.getenv("SECRET")', True),
            ("api_key = process.env.API_KEY", True),
            # Function signatures
            ("def set_password(self, password):", True),
            # SQL DDL
            ("password VARCHAR(255)", True),
            # Real secrets — should NOT be detected
            ('password = "SuperS3cret!Value"', False),
        ],
    )
    def test_code_declaration(self, line, expected):
        """Test that code declarations are correctly identified."""
        is_decl, reason = is_code_declaration(line)
        assert is_decl == expected, f"Expected {expected} for: {line!r}, got {is_decl} (reason: {reason})"


class TestLowEntropyValue:
    """Test is_low_entropy_value() for generic pattern FP reduction."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            # Known keywords — should be detected
            ("password", True),
            ("secret", True),
            ("string", True),
            ("none", True),
            ("required", True),
            # Repeating characters
            ("xxxxxxxx", True),
            ("********", True),
            # Single plain words
            ("mypassword", True),
            # Real secrets — should NOT be detected
            ("S3cretV@lue!123", False),
            ("abc123def456ghi", False),
            ("xK9mP2nQ5rT8wY1", False),
        ],
    )
    def test_low_entropy_value(self, value, expected):
        """Test that low-entropy values are correctly identified."""
        is_low, reason = is_low_entropy_value(value)
        assert is_low == expected, f"Expected {expected} for: {value!r}, got {is_low} (reason: {reason})"


class TestFalsePositiveReduction:
    """Integration tests verifying FP detection in scan_file."""

    def test_type_annotation_flagged_as_fp(self):
        """Test that type annotations are flagged as false positives."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("class User:\n")
            f.write("    password: str\n")
            f.write("    secret: str\n")
            f.flush()

            findings = scan_file(f.name)

            # Any generic findings should be marked as FP
            generic_findings = [
                finding for finding in findings
                if finding.type in ("generic_secret", "generic_api_key")
            ]
            for finding in generic_findings:
                assert finding.likely_false_positive, (
                    f"Expected FP for {finding.type} at line {finding.line}"
                )
                assert finding.fp_reason is not None

        Path(f.name).unlink()

    def test_real_secret_not_flagged_as_fp(self):
        """Test that real hardcoded secrets are NOT flagged as false positive."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('password = "S3cretV@lue!123"\n')
            f.flush()

            findings = scan_file(f.name)

            generic_findings = [
                finding for finding in findings
                if finding.type in ("generic_secret", "generic_api_key")
            ]
            assert len(generic_findings) >= 1
            # Real secrets should NOT be flagged as false positive
            for finding in generic_findings:
                assert not finding.likely_false_positive, (
                    f"Real secret should not be FP: {finding.fp_reason}"
                )

        Path(f.name).unlink()

    def test_env_var_reference_flagged_as_fp(self):
        """Test that env var references are flagged as false positives."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('password = os.environ["DATABASE_PASSWORD"]\n')
            f.flush()

            findings = scan_file(f.name)

            generic_findings = [
                finding for finding in findings
                if finding.type in ("generic_secret", "generic_api_key")
            ]
            for finding in generic_findings:
                assert finding.likely_false_positive

        Path(f.name).unlink()

    def test_structured_patterns_not_affected(self):
        """Test that structured patterns (AWS, Stripe) are NOT affected by FP detection."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
            f.flush()

            findings = scan_file(f.name)

            aws_findings = [f for f in findings if f.type == "aws_access_key_id"]
            assert len(aws_findings) >= 1
            # AWS key pattern should NOT have code declaration FP logic applied
            # (it's already flagged as test data due to EXAMPLE in value)
            for finding in aws_findings:
                if finding.likely_false_positive and finding.fp_reason:
                    # Should only be test data, not code declaration
                    assert "Code declaration" not in finding.fp_reason

        Path(f.name).unlink()
