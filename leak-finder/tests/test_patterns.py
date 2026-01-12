"""Tests for secret detection patterns."""

import pytest

from leak_finder.patterns import SECRET_PATTERNS


class TestPatterns:
    """Test each regex pattern with known examples."""

    def test_aws_access_key_id(self):
        """Test AWS Access Key ID detection."""
        pattern = SECRET_PATTERNS["aws_access_key_id"]["regex"]
        # Valid AWS key
        assert pattern.search("AKIAIOSFODNN7EXAMPLE")
        assert pattern.search("ASIAISAMPLEKEYID1234")
        # Invalid
        assert not pattern.search("INVALID1234567890123")
        assert not pattern.search("notakey")

    def test_aws_secret_access_key(self):
        """Test AWS Secret Access Key detection."""
        pattern = SECRET_PATTERNS["aws_secret_access_key"]["regex"]
        assert pattern.search('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
        # Pattern requires 40 chars for the secret value
        assert pattern.search("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    def test_stripe_live_key(self):
        """Test Stripe live secret key detection."""
        pattern = SECRET_PATTERNS["stripe_live_key"]["regex"]
        assert pattern.search("sk_live_1234567890abcdefghijklmnop")
        assert not pattern.search("sk_test_1234567890abcdefghijklmnop")

    def test_stripe_test_key(self):
        """Test Stripe test secret key detection."""
        pattern = SECRET_PATTERNS["stripe_test_key"]["regex"]
        assert pattern.search("sk_test_1234567890abcdefghijklmnop")
        assert not pattern.search("sk_live_1234567890abcdefghijklmnop")

    def test_github_pat(self):
        """Test GitHub Personal Access Token detection."""
        pattern = SECRET_PATTERNS["github_pat"]["regex"]
        assert pattern.search("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        assert not pattern.search("ghp_short")

    def test_github_oauth(self):
        """Test GitHub OAuth token detection."""
        pattern = SECRET_PATTERNS["github_oauth"]["regex"]
        assert pattern.search("gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

    def test_private_key_rsa(self):
        """Test RSA private key detection."""
        pattern = SECRET_PATTERNS["private_key_rsa"]["regex"]
        assert pattern.search("-----BEGIN RSA PRIVATE KEY-----")
        assert not pattern.search("-----BEGIN PUBLIC KEY-----")

    def test_private_key_openssh(self):
        """Test OpenSSH private key detection."""
        pattern = SECRET_PATTERNS["private_key_openssh"]["regex"]
        assert pattern.search("-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_private_key_ec(self):
        """Test EC private key detection."""
        pattern = SECRET_PATTERNS["private_key_ec"]["regex"]
        assert pattern.search("-----BEGIN EC PRIVATE KEY-----")

    def test_postgres_uri(self):
        """Test PostgreSQL connection URI detection."""
        pattern = SECRET_PATTERNS["postgres_uri"]["regex"]
        assert pattern.search("postgres://user:password@localhost:5432/db")
        assert pattern.search("postgresql://admin:secret123@host.com/production")
        assert not pattern.search("postgres://localhost/db")  # No password

    def test_mysql_uri(self):
        """Test MySQL connection URI detection."""
        pattern = SECRET_PATTERNS["mysql_uri"]["regex"]
        assert pattern.search("mysql://root:password@localhost/mydb")

    def test_slack_token(self):
        """Test Slack token detection."""
        pattern = SECRET_PATTERNS["slack_token"]["regex"]
        assert pattern.search("xoxb-1234567890-abcdefghij")
        assert pattern.search("xoxp-1234567890-abcdefghij")

    def test_sendgrid_api_key(self):
        """Test SendGrid API key detection."""
        pattern = SECRET_PATTERNS["sendgrid_api_key"]["regex"]
        assert pattern.search("SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

    def test_generic_api_key(self):
        """Test generic API key detection."""
        pattern = SECRET_PATTERNS["generic_api_key"]["regex"]
        assert pattern.search("api_key = 'abcdefghijklmnopqrstuvwxyz'")
        assert pattern.search('apikey: "12345678901234567890"')

    def test_generic_secret(self):
        """Test generic secret/password detection."""
        pattern = SECRET_PATTERNS["generic_secret"]["regex"]
        assert pattern.search("password = 'mysecretpassword123'")
        assert pattern.search('secret: "topsecret!"')

    def test_all_patterns_have_required_fields(self):
        """Test all patterns have regex, severity, and description."""
        for name, pattern_info in SECRET_PATTERNS.items():
            assert "regex" in pattern_info, f"{name} missing regex"
            assert "severity" in pattern_info, f"{name} missing severity"
            assert "description" in pattern_info, f"{name} missing description"
            assert pattern_info["severity"] in ["critical", "high", "medium", "low", "info"]

    def test_pattern_count(self):
        """Test we have at least 15 patterns."""
        assert len(SECRET_PATTERNS) >= 15
