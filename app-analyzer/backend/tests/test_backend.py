import io
import zipfile
import pytest
from pathlib import Path
from app.core.security import SecurityValidator, InMemoryRateLimiter
from app.engines.scoring import ScoringEngine
from app.engines.apk_analyzer import APKAnalyzer
from app.engines.pe_analyzer import PEAnalyzer
from app.models.schemas import SecurityFinding, SeverityLevel, ProductionGate

def test_security_validator_sanitize_filename():
    assert SecurityValidator.sanitize_filename("../../etc/passwd") == "passwd"
    assert SecurityValidator.sanitize_filename("app;calc.exe") == "app_calc.exe"
    assert SecurityValidator.sanitize_filename("normal_app.apk") == "normal_app.apk"

def test_rate_limiter():
    limiter = InMemoryRateLimiter(requests_per_minute=2)
    assert limiter.is_allowed("192.168.1.1") is True
    assert limiter.is_allowed("192.168.1.1") is True
    assert limiter.is_allowed("192.168.1.1") is False
    assert limiter.is_allowed("192.168.1.2") is True

def test_scoring_engine_critical_blocks_production():
    findings = [
        SecurityFinding(
            severity=SeverityLevel.CRITICAL,
            category="Manifest",
            title="Debuggable enabled",
            description="App is debuggable",
            cwe="CWE-215",
            remediation="Set debuggable false"
        ),
        SecurityFinding(
            severity=SeverityLevel.MEDIUM,
            category="Hardening",
            title="Backup enabled",
            description="ADB backup allowed",
            cwe="CWE-921",
            remediation="Set allowBackup false"
        )
    ]
    summary, improvements, prompt = ScoringEngine.evaluate(findings, ".apk", "test.apk")
    assert summary.productionGate == ProductionGate.BLOCKED
    assert summary.criticalCount == 1
    assert summary.hackabilityScore >= 4.0
    assert len(improvements) >= 2
    assert "Debuggable" in prompt

def test_scoring_engine_clean_binary():
    findings = []
    summary, improvements, prompt = ScoringEngine.evaluate(findings, ".exe", "secure.exe")
    assert summary.productionGate == ProductionGate.READY
    assert summary.hackabilityScore == 1.0
    assert summary.criticalCount == 0

def test_apk_analyzer_with_synthetic_apk(tmp_path: Path):
    apk_file = tmp_path / "sample.apk"
    manifest_xml = b"""<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
        <uses-permission android:name="android.permission.RECORD_AUDIO" />
        <application android:debuggable="true" android:usesCleartextTraffic="true">
            <activity android:name=".MainActivity" android:exported="true" />
        </application>
    </manifest>"""

    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml)
        zf.writestr("classes.dex", b"test_string_with_AKIAIOSFODNN7EXAMPLE_key")

    is_valid, err = SecurityValidator.validate_apk_package(apk_file)
    assert is_valid is True

    analyzer = APKAnalyzer()
    res = analyzer.analyze(apk_file)
    findings = res["findings"]

    titles = [f.title for f in findings]
    assert any("Debuggable" in t for t in titles)
    assert any("Cleartext" in t for t in titles)
    assert any("AWS Access Key" in t for t in titles)
