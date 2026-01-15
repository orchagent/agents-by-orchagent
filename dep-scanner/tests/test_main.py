"""Tests for dep-scanner main API."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile

from httpx import AsyncClient, ASGITransport

from dep_scanner.main import app
from dep_scanner.models import Finding, ScanResponse, ScanSummary
from dep_scanner.scanners.npm import parse_npm_audit_output
from dep_scanner.scanners.pip import parse_pip_audit_output, determine_severity


@pytest.fixture
def test_client():
    """Create async test client for FastAPI."""
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


class TestHealthEndpoint:
    """Test /health endpoint."""

    @pytest.mark.asyncio
    async def test_health_returns_ok(self, test_client):
        """Test that /health endpoint returns status ok."""
        async with test_client as client:
            response = await client.get("/health")

            assert response.status_code == 200
            assert response.json() == {"status": "ok"}


class TestScanEndpoint:
    """Test /scan endpoint."""

    @pytest.mark.asyncio
    async def test_scan_with_mock_git_clone(self, test_client):
        """Test /scan endpoint with mocked git clone."""
        mock_response = ScanResponse(
            scan_id="test-uuid",
            detected_managers=["npm"],
            findings=[
                Finding(
                    package="lodash",
                    version="4.17.20",
                    severity="high",
                    cve="CVE-2021-23337",
                    title="Command Injection in lodash",
                    fixed_in="4.17.21",
                    recommendation="Run: npm update lodash",
                )
            ],
            summary=ScanSummary(
                critical=0,
                high=1,
                medium=0,
                low=0,
                total_packages_scanned=100,
            ),
        )

        with patch("dep_scanner.main.scan_repository", return_value=mock_response):
            async with test_client as client:
                response = await client.post(
                    "/scan",
                    json={"repo_url": "https://github.com/example/repo.git"},
                )

                assert response.status_code == 200
                data = response.json()
                assert data["scan_id"] == "test-uuid"
                assert data["detected_managers"] == ["npm"]
                assert len(data["findings"]) == 1
                assert data["findings"][0]["package"] == "lodash"
                assert data["summary"]["high"] == 1

    @pytest.mark.asyncio
    async def test_scan_with_severity_threshold(self, test_client):
        """Test /scan endpoint respects severity threshold."""
        mock_response = ScanResponse(
            scan_id="test-uuid",
            detected_managers=["npm"],
            findings=[
                Finding(
                    package="axios",
                    version="0.21.0",
                    severity="high",
                    cve="CVE-2021-3749",
                    title="Inefficient Regular Expression Complexity",
                    fixed_in="0.21.2",
                    recommendation="Run: npm update axios",
                )
            ],
            summary=ScanSummary(critical=0, high=1, medium=0, low=0),
        )

        with patch("dep_scanner.main.scan_repository", return_value=mock_response):
            async with test_client as client:
                response = await client.post(
                    "/scan",
                    json={
                        "repo_url": "https://github.com/example/repo.git",
                        "severity_threshold": "high",
                    },
                )

                assert response.status_code == 200
                data = response.json()
                assert len(data["findings"]) == 1
                assert data["findings"][0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_scan_with_invalid_repo_url(self, test_client):
        """Test /scan endpoint with invalid repository URL."""
        from git.exc import GitCommandError

        with patch(
            "dep_scanner.main.scan_repository",
            side_effect=GitCommandError("git clone", 128),
        ):
            async with test_client as client:
                response = await client.post(
                    "/scan",
                    json={"repo_url": "https://github.com/invalid/repo.git"},
                )

                assert response.status_code == 400
                assert "Failed to clone repository" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_scan_with_no_vulnerabilities(self, test_client):
        """Test /scan endpoint when no vulnerabilities are found."""
        mock_response = ScanResponse(
            scan_id="test-uuid",
            detected_managers=["npm", "pip"],
            findings=[],
            summary=ScanSummary(
                critical=0, high=0, medium=0, low=0, total_packages_scanned=50
            ),
        )

        with patch("dep_scanner.main.scan_repository", return_value=mock_response):
            async with test_client as client:
                response = await client.post(
                    "/scan",
                    json={"repo_url": "https://github.com/example/repo.git"},
                )

                assert response.status_code == 200
                data = response.json()
                assert len(data["findings"]) == 0
                assert data["detected_managers"] == ["npm", "pip"]


class TestNpmAuditParsing:
    """Test npm audit output parsing."""

    def test_parse_npm_audit_with_vulnerabilities(self):
        """Test parsing npm audit output with vulnerabilities."""
        npm_audit_output = """{
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "via": [
                        {
                            "source": 1065,
                            "name": "lodash",
                            "dependency": "lodash",
                            "title": "Command Injection",
                            "url": "https://npmjs.com/advisories/1065",
                            "severity": "high",
                            "cve": "CVE-2021-23337",
                            "range": "<4.17.21"
                        }
                    ],
                    "effects": [],
                    "range": "<4.17.21",
                    "nodes": ["node_modules/lodash"],
                    "fixAvailable": {
                        "name": "lodash",
                        "version": "4.17.21"
                    }
                }
            },
            "metadata": {
                "vulnerabilities": {
                    "info": 0, "low": 0, "moderate": 0, "high": 1, "critical": 0, "total": 1
                }
            }
        }"""

        findings = parse_npm_audit_output(npm_audit_output)

        assert len(findings) == 1
        assert findings[0].package == "lodash"
        assert findings[0].severity == "high"
        assert findings[0].cve == "CVE-2021-23337"
        assert findings[0].title == "Command Injection"
        assert findings[0].fixed_in == "4.17.21"
        assert "npm update" in findings[0].recommendation

    def test_parse_npm_audit_with_moderate_severity(self):
        """Test that 'moderate' is mapped to 'medium'."""
        npm_audit_output = """{
            "vulnerabilities": {
                "minimist": {
                    "name": "minimist",
                    "severity": "moderate",
                    "via": [
                        {
                            "source": 1179,
                            "name": "minimist",
                            "title": "Prototype Pollution",
                            "severity": "moderate",
                            "cve": "CVE-2020-7598",
                            "range": "<0.2.1"
                        }
                    ],
                    "fixAvailable": true
                }
            }
        }"""

        findings = parse_npm_audit_output(npm_audit_output)

        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_parse_npm_audit_no_vulnerabilities(self):
        """Test parsing npm audit output with no vulnerabilities."""
        npm_audit_output = """{
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": {
                    "info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0
                }
            }
        }"""

        findings = parse_npm_audit_output(npm_audit_output)

        assert len(findings) == 0

    def test_parse_npm_audit_transitive_dependency(self):
        """Test parsing npm audit output with transitive dependency (string via)."""
        npm_audit_output = """{
            "vulnerabilities": {
                "ansi-regex": {
                    "name": "ansi-regex",
                    "severity": "high",
                    "via": ["string-width"],
                    "effects": [],
                    "fixAvailable": true
                },
                "string-width": {
                    "name": "string-width",
                    "severity": "high",
                    "via": [
                        {
                            "source": 1234,
                            "name": "string-width",
                            "title": "ReDoS",
                            "severity": "high",
                            "cve": "CVE-2021-3807",
                            "range": "<4.2.3"
                        }
                    ],
                    "fixAvailable": true
                }
            }
        }"""

        findings = parse_npm_audit_output(npm_audit_output)

        # Should only find string-width (the direct vulnerability), not ansi-regex
        assert len(findings) == 1
        assert findings[0].package == "string-width"

    def test_parse_npm_audit_invalid_json(self):
        """Test parsing invalid JSON returns empty list."""
        findings = parse_npm_audit_output("not valid json")

        assert findings == []


class TestPipAuditParsing:
    """Test pip-audit output parsing."""

    def test_parse_pip_audit_with_vulnerabilities(self):
        """Test parsing pip-audit output with vulnerabilities."""
        pip_audit_output = """[
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [
                    {
                        "id": "GHSA-j8r2-6x86-q33q",
                        "fix_versions": ["2.31.0"],
                        "aliases": ["CVE-2023-32681"],
                        "description": "Unintended leak of Proxy-Authorization header in requests"
                    }
                ]
            }
        ]"""

        findings = parse_pip_audit_output(pip_audit_output)

        assert len(findings) == 1
        assert findings[0].package == "requests"
        assert findings[0].version == "2.25.0"
        assert findings[0].cve == "CVE-2023-32681"
        assert findings[0].fixed_in == "2.31.0"
        assert "pip install --upgrade" in findings[0].recommendation

    def test_parse_pip_audit_dict_format(self):
        """Test parsing pip-audit output in dict format."""
        pip_audit_output = """{
            "dependencies": [
                {
                    "name": "urllib3",
                    "version": "1.26.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2021-108",
                            "fix_versions": ["1.26.5"],
                            "aliases": ["CVE-2021-33503"],
                            "description": "urllib3 can cause Denial of Service when parsing URLs"
                        }
                    ]
                }
            ],
            "fixes": []
        }"""

        findings = parse_pip_audit_output(pip_audit_output)

        assert len(findings) == 1
        assert findings[0].package == "urllib3"
        assert findings[0].cve == "CVE-2021-33503"

    def test_parse_pip_audit_no_vulnerabilities(self):
        """Test parsing pip-audit output with no vulnerabilities."""
        pip_audit_output = "[]"

        findings = parse_pip_audit_output(pip_audit_output)

        assert len(findings) == 0

    def test_parse_pip_audit_no_fix_available(self):
        """Test parsing when no fix is available."""
        pip_audit_output = """[
            {
                "name": "example-pkg",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "GHSA-xxxx-yyyy-zzzz",
                        "fix_versions": [],
                        "aliases": [],
                        "description": "Some vulnerability"
                    }
                ]
            }
        ]"""

        findings = parse_pip_audit_output(pip_audit_output)

        assert len(findings) == 1
        assert findings[0].fixed_in == "no fix available"
        assert "consider replacing" in findings[0].recommendation.lower()

    def test_parse_pip_audit_invalid_json(self):
        """Test parsing invalid JSON returns empty list."""
        findings = parse_pip_audit_output("not valid json")

        assert findings == []


class TestDetermineSeverity:
    """Test severity determination for pip-audit findings."""

    def test_determine_severity_critical(self):
        """Test critical severity detection."""
        vuln = {"description": "Remote code execution vulnerability"}
        assert determine_severity(vuln) == "critical"

        vuln = {"description": "RCE in package"}
        assert determine_severity(vuln) == "critical"

    def test_determine_severity_high(self):
        """Test high severity detection."""
        vuln = {"description": "SQL injection vulnerability"}
        assert determine_severity(vuln) == "high"

        vuln = {"description": "Command injection in parser"}
        assert determine_severity(vuln) == "high"

    def test_determine_severity_medium(self):
        """Test medium severity detection."""
        vuln = {"description": "Denial of service when parsing large files"}
        assert determine_severity(vuln) == "medium"

    def test_determine_severity_explicit(self):
        """Test when severity is explicitly provided."""
        vuln = {"severity": "LOW", "description": "Some issue"}
        assert determine_severity(vuln) == "low"

    def test_determine_severity_default(self):
        """Test default severity when nothing matches."""
        vuln = {"description": "Some random issue"}
        assert determine_severity(vuln) == "medium"
