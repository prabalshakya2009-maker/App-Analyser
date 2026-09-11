import re
import zipfile
from pathlib import Path
from typing import Dict, Any, List
from ..models.schemas import SecurityFinding, SeverityLevel

class APKAnalyzer:
    DANGEROUS_PERMISSIONS = {
        "android.permission.SEND_SMS": ("SMS Manipulation", SeverityLevel.HIGH, "CWE-250"),
        "android.permission.RECEIVE_SMS": ("SMS Snooping", SeverityLevel.HIGH, "CWE-250"),
        "android.permission.READ_SMS": ("SMS Reading", SeverityLevel.HIGH, "CWE-250"),
        "android.permission.RECORD_AUDIO": ("Microphone Eavesdropping", SeverityLevel.MEDIUM, "CWE-250"),
        "android.permission.CAMERA": ("Camera Access", SeverityLevel.MEDIUM, "CWE-250"),
        "android.permission.ACCESS_FINE_LOCATION": ("Precise GPS Tracking", SeverityLevel.MEDIUM, "CWE-250"),
        "android.permission.READ_CONTACTS": ("Address Book Exfiltration", SeverityLevel.MEDIUM, "CWE-250"),
        "android.permission.READ_CALL_LOG": ("Call Log Access", SeverityLevel.HIGH, "CWE-250"),
        "android.permission.SYSTEM_ALERT_WINDOW": ("Overlay Attack Vulnerability", SeverityLevel.HIGH, "CWE-1021"),
        "android.permission.REQUEST_INSTALL_PACKAGES": ("Arbitrary APK Installation", SeverityLevel.HIGH, "CWE-494"),
    }

    SECRET_PATTERNS = [
        (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key", SeverityLevel.CRITICAL, "CWE-798"),
        (re.compile(r'AIza[0-9A-Za-z-_]{35}'), "Google API Key", SeverityLevel.HIGH, "CWE-798"),
        (re.compile(r'sk_live_[0-9a-zA-Z]{24}'), "Stripe Live Secret Key", SeverityLevel.CRITICAL, "CWE-798"),
        (re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'), "Slack Token", SeverityLevel.HIGH, "CWE-798"),
        (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), "Hardcoded JWT Token", SeverityLevel.CRITICAL, "CWE-798"),
        (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "Embedded RSA/EC Private Key", SeverityLevel.CRITICAL, "CWE-312")
    ]

    def analyze(self, file_path: Path) -> Dict[str, Any]:
        findings: List[SecurityFinding] = []
        static_details: Dict[str, Any] = {
            "format": "Android APK",
            "permissions": [],
            "dangerousPermissions": [],
            "exportedComponents": [],
            "hasNetworkSecurityConfig": False,
            "dexFileCount": 0,
            "isDebugSigned": False,
        }

        with zipfile.ZipFile(file_path, "r") as zf:
            namelist = zf.namelist()

            manifest_bytes = zf.read("AndroidManifest.xml")
            self._analyze_manifest(manifest_bytes, findings, static_details)

            static_details["hasNetworkSecurityConfig"] = any("network_security_config" in name for name in namelist)
            if not static_details["hasNetworkSecurityConfig"]:
                findings.append(SecurityFinding(
                    severity=SeverityLevel.MEDIUM,
                    category="Network Security",
                    title="Missing Network Security Configuration",
                    description="The application does not declare res/xml/network_security_config.xml. Cannot enforce domain-level TLS certificate pinning.",
                    cwe="CWE-295",
                    remediation="Add android:networkSecurityConfig='@xml/network_security_config' to enforce strict TLS pinsets.",
                    evidence="res/xml/network_security_config.xml missing"
                ))

            dex_names = [n for n in namelist if n.endswith(".dex")]
            static_details["dexFileCount"] = len(dex_names)
            for dex_name in dex_names:
                dex_bytes = zf.read(dex_name)
                self._scan_dex_secrets(dex_bytes, dex_name, findings)

            self._check_signing(zf, namelist, findings, static_details)

        return {
            "findings": findings,
            "staticDetails": static_details
        }

    def _analyze_manifest(self, manifest_bytes: bytes, findings: List[SecurityFinding], details: Dict[str, Any]):
        text = manifest_bytes.decode('utf-8', errors='ignore')

        if "debuggable" in text.lower():
            if re.search(r'debuggable\s*=\s*(?:["\']?true["\']?|\x01)', text, re.I):
                findings.append(SecurityFinding(
                    severity=SeverityLevel.CRITICAL,
                    category="Manifest Security",
                    title="Application is Debuggable in Release Mode",
                    description="android:debuggable='true' allows any local attacker or malware to attach a debugger (jdb/gdb), dump memory, and execute arbitrary code.",
                    cwe="CWE-215",
                    remediation="Set android:debuggable='false' in release build configurations.",
                    evidence="android:debuggable enabled"
                ))

        if "usescleartexttraffic" in text.lower():
            if re.search(r'usesCleartextTraffic\s*=\s*(?:["\']?true["\']?|\x01)', text, re.I):
                findings.append(SecurityFinding(
                    severity=SeverityLevel.HIGH,
                    category="Network Security",
                    title="Cleartext Traffic Permitted (HTTP MitM Risk)",
                    description="android:usesCleartextTraffic='true' allows unencrypted HTTP network communication, vulnerable to on-path interception.",
                    cwe="CWE-319",
                    remediation="Set android:usesCleartextTraffic='false' and mandate TLS 1.3 across all network calls.",
                    evidence="android:usesCleartextTraffic enabled"
                ))

        if "allowbackup" in text.lower():
            if re.search(r'allowBackup\s*=\s*(?:["\']?true["\']?|\x01)', text, re.I):
                findings.append(SecurityFinding(
                    severity=SeverityLevel.MEDIUM,
                    category="Data Storage & Backup",
                    title="Application Backup Enabled (ADB Data Leak)",
                    description="android:allowBackup='true' enables an attacker with physical or ADB access to dump application databases, Shared Preferences, and tokens.",
                    cwe="CWE-921",
                    remediation="Set android:allowBackup='false' in AndroidManifest.xml.",
                    evidence="android:allowBackup enabled"
                ))

        for perm, (threat, severity, cwe) in self.DANGEROUS_PERMISSIONS.items():
            short_perm = perm.split(".")[-1]
            if short_perm in text or perm in text:
                details["permissions"].append(perm)
                details["dangerousPermissions"].append(perm)
                findings.append(SecurityFinding(
                    severity=severity,
                    category="Dangerous Permissions",
                    title=f"Excessive Permission: {short_perm}",
                    description=f"App requests {perm}, granting potential for {threat.lower()}.",
                    cwe=cwe,
                    remediation="Audit necessity. Rely on Android Storage Access Framework or Camera Intents instead of broad permission grants.",
                    evidence=perm
                ))

        exported_matches = re.findall(r'<(?:activity|service|receiver|provider)[^>]*android:exported\s*=\s*["\']true["\']', text, re.I)
        if exported_matches:
            count = len(exported_matches)
            details["exportedComponents"] = [m[:60] for m in exported_matches[:10]]
            findings.append(SecurityFinding(
                severity=SeverityLevel.HIGH,
                category="Component Exposure",
                title=f"{count} Unprotected Exported Component(s) Found",
                description="Application exposes Android components with android:exported='true'. Malicious apps on the same device can trigger these components.",
                cwe="CWE-926",
                remediation="Explicitly set android:exported='false' or protect exported components with strict custom android:permission attributes.",
                evidence=f"{count} components explicitly exported"
            ))

    def _scan_dex_secrets(self, dex_bytes: bytes, dex_name: str, findings: List[SecurityFinding]):
        text = dex_bytes.decode('ascii', errors='ignore')
        for pattern, title, severity, cwe in self.SECRET_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                sample = str(matches[0])[:50]
                findings.append(SecurityFinding(
                    severity=severity,
                    category="Hardcoded Secrets & Bytecode Credentials",
                    title=f"{title} in Bytecode ({dex_name})",
                    description=f"High-entropy secret pattern discovered in compiled DEX bytecode: {title}.",
                    cwe=cwe,
                    remediation="Do not hardcode secrets into compiled client binaries. Inject credentials dynamically at runtime via a secured backend proxy.",
                    evidence=f"{dex_name} -> {sample}"
                ))

    def _check_signing(self, zf: zipfile.ZipFile, namelist: List[str], findings: List[SecurityFinding], details: Dict[str, Any]):
        sig_files = [n for n in namelist if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))]
        if not sig_files:
            findings.append(SecurityFinding(
                severity=SeverityLevel.CRITICAL,
                category="Code Integrity & Signature",
                title="Unsigned APK Package",
                description="APK lacks a valid META-INF signature block. Android Package Manager will refuse installation.",
                cwe="CWE-347",
                remediation="Sign the APK using apksigner with a secure production keystore.",
                evidence="No META-INF signature file"
            ))
        else:
            for sf in sig_files:
                sig_data = zf.read(sf).decode('latin1', errors='ignore')
                if "Android Debug" in sig_data or "debug.keystore" in sig_data:
                    details["isDebugSigned"] = True
                    findings.append(SecurityFinding(
                        severity=SeverityLevel.CRITICAL,
                        category="Code Integrity & Signature",
                        title="Signed with Insecure Android Debug Keystore",
                        description="The APK was signed with the default, publicly known Android Debug key (CN=Android Debug). Anyone can spoof updates.",
                        cwe="CWE-295",
                        remediation="Sign production releases with a private, password-protected production release keystore.",
                        evidence=f"CN=Android Debug found in {sf}"
                    ))
                    break
