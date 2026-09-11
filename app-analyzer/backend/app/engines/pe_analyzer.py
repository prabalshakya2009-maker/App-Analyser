import math
import re
import struct
from pathlib import Path
from typing import Dict, Any, List
from ..models.schemas import SecurityFinding, SeverityLevel

class PEAnalyzer:
    DANGEROUS_APIS = {
        "Memory Injection / Alteration": [
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
            "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "SetThreadContext"
        ],
        "Process Spawning / Execution": [
            "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW"
        ],
        "Anti-Analysis / Debug Evasion": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"
        ],
        "Input Snooping / Keylogging": [
            "GetAsyncKeyState", "GetKeyState", "SetWindowsHookExA", "SetWindowsHookExW"
        ],
        "Arbitrary Network Download": [
            "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW"
        ]
    }

    SUSPICIOUS_STRINGS = [
        (re.compile(r'powershell(?:\.exe)?\s+-[eE](?:nc(?:odedcommand)?)?', re.I), "Encoded PowerShell Execution", SeverityLevel.CRITICAL, "CWE-78"),
        (re.compile(r'cmd\.exe\s+/c', re.I), "Command Shell Invocation", SeverityLevel.HIGH, "CWE-78"),
        (re.compile(r'AKIA[0-9A-Z]{16}'), "Exposed AWS Access Key", SeverityLevel.CRITICAL, "CWE-798"),
        (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "Exposed Cryptographic Private Key", SeverityLevel.CRITICAL, "CWE-312"),
    ]

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for i in range(256):
            p_x = data.count(bytes([i])) / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return round(entropy, 3)

    def analyze(self, file_path: Path) -> Dict[str, Any]:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        findings: List[SecurityFinding] = []
        static_details: Dict[str, Any] = {
            "format": "PE32/PE32+",
            "sections": [],
            "mitigations": {},
            "imports": [],
            "isSigned": False,
        }

        try:
            import pefile
            pe = pefile.PE(data=raw_bytes)
            self._analyze_with_pefile(pe, findings, static_details)
        except Exception:
            self._analyze_raw_fallback(raw_bytes, findings, static_details)

        self._scan_strings(raw_bytes, findings)

        return {
            "findings": findings,
            "staticDetails": static_details
        }

    def _analyze_with_pefile(self, pe: Any, findings: List[SecurityFinding], details: Dict[str, Any]):
        dll_chars = getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)

        aslr = bool(dll_chars & 0x0040)
        dep = bool(dll_chars & 0x0100)
        cfg = bool(dll_chars & 0x4000)
        high_entropy_va = bool(dll_chars & 0x0020)

        has_security_dir = False
        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
                sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
                has_security_dir = sec_dir.VirtualAddress != 0 and sec_dir.Size != 0

        details["mitigations"] = {
            "ASLR": aslr,
            "DEP_NX": dep,
            "ControlFlowGuard": cfg,
            "HighEntropyVA": high_entropy_va,
            "DigitalSignature": has_security_dir
        }
        details["isSigned"] = has_security_dir

        if not aslr:
            findings.append(SecurityFinding(
                severity=SeverityLevel.HIGH,
                category="Binary Hardening",
                title="Address Space Layout Randomization (ASLR) Missing",
                description="Binary lacks DYNAMIC_BASE flag. Code offsets are static in memory, leaving it vulnerable to Return-Oriented Programming (ROP).",
                cwe="CWE-119",
                remediation="Enable ASLR in your compiler/linker (e.g., MSVC /DYNAMICBASE, GCC -fPIE -pie).",
                evidence="DllCharacteristics DYNAMIC_BASE bit unset (0x0040 missing)"
            ))

        if not dep:
            findings.append(SecurityFinding(
                severity=SeverityLevel.CRITICAL,
                category="Binary Hardening",
                title="Data Execution Prevention (DEP / NX) Disabled",
                description="Binary is missing NX_COMPAT. Stack and heap memory pages may be executable, permitting direct shellcode execution.",
                cwe="CWE-119",
                remediation="Compile with Data Execution Prevention enabled (MSVC /NXCOMPAT, GCC -z noexecstack).",
                evidence="DllCharacteristics NX_COMPAT bit unset (0x0100 missing)"
            ))

        if not cfg:
            findings.append(SecurityFinding(
                severity=SeverityLevel.MEDIUM,
                category="Binary Hardening",
                title="Control Flow Guard (CFG) Inactive",
                description="Binary does not validate indirect call targets against a known bitmap table.",
                cwe="CWE-691",
                remediation="Compile with Control Flow Guard enabled (MSVC /guard:cf).",
                evidence="DllCharacteristics GUARD_CF bit unset (0x4000 missing)"
            ))

        if not has_security_dir:
            findings.append(SecurityFinding(
                severity=SeverityLevel.HIGH,
                category="Integrity & Trust",
                title="Unsigned Executable Binary",
                description="Binary lacks an embedded Authenticode digital signature. Integrity cannot be verified by Windows Defender SmartScreen.",
                cwe="CWE-347",
                remediation="Sign the binary using an Authenticode Code Signing certificate (signtool sign /fd SHA256).",
                evidence="IMAGE_DIRECTORY_ENTRY_SECURITY empty"
            ))

        for section in pe.sections:
            sec_name = section.Name.decode(errors='ignore').rstrip('\x00')
            entropy = section.get_entropy()
            details["sections"].append({
                "name": sec_name,
                "virtualSize": section.Misc_VirtualSize,
                "rawSize": section.SizeOfRawData,
                "entropy": round(entropy, 3)
            })

            if entropy > 7.2:
                findings.append(SecurityFinding(
                    severity=SeverityLevel.MEDIUM,
                    category="Packer & Obfuscation",
                    title=f"High Section Entropy ({sec_name}: {entropy:.2f})",
                    description=f"Section {sec_name} exhibits high Shannon entropy (>7.2), typically indicating compression, encryption, or packing.",
                    cwe="CWE-506",
                    remediation="If packing is intentional, document it; otherwise inspect for unintended payload injection.",
                    evidence=f"Section: {sec_name}, Entropy: {entropy:.3f}"
                ))

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        api = imp.name.decode(errors='ignore')
                        details["imports"].append(f"{dll}!{api}")
                        for category, apis in self.DANGEROUS_APIS.items():
                            if any(api.lower().startswith(d.lower()) for d in apis):
                                findings.append(SecurityFinding(
                                    severity=SeverityLevel.MEDIUM,
                                    category="Dangerous API Usage",
                                    title=f"High-Risk API Imported: {api} ({category})",
                                    description=f"Executable statically imports {api} from {dll}, capable of {category.lower()}.",
                                    cwe="CWE-250",
                                    remediation=f"Audit usage of {api}. Prefer secure managed alternatives if dynamic memory manipulation is not mandatory.",
                                    evidence=f"{dll}!{api}"
                                ))

    def _analyze_raw_fallback(self, raw_bytes: bytes, findings: List[SecurityFinding], details: Dict[str, Any]):
        pe_offset = struct.unpack("<I", raw_bytes[60:64])[0]
        opt_header_offset = pe_offset + 24
        magic = struct.unpack("<H", raw_bytes[opt_header_offset:opt_header_offset + 2])[0]
        dll_chars_offset = opt_header_offset + (70 if magic == 0x10b else 70)
        dll_chars = struct.unpack("<H", raw_bytes[dll_chars_offset:dll_chars_offset + 2])[0]

        aslr = bool(dll_chars & 0x0040)
        dep = bool(dll_chars & 0x0100)

        details["mitigations"] = {"ASLR": aslr, "DEP_NX": dep, "DigitalSignature": False}
        if not aslr:
            findings.append(SecurityFinding(
                severity=SeverityLevel.HIGH,
                category="Binary Hardening",
                title="Address Space Layout Randomization (ASLR) Missing",
                description="Binary lacks DYNAMIC_BASE flag.",
                cwe="CWE-119",
                remediation="Compile with /DYNAMICBASE.",
                evidence="Raw header DllCharacteristics offset"
            ))
        if not dep:
            findings.append(SecurityFinding(
                severity=SeverityLevel.CRITICAL,
                category="Binary Hardening",
                title="Data Execution Prevention (DEP / NX) Disabled",
                description="Binary is missing NX_COMPAT.",
                cwe="CWE-119",
                remediation="Compile with /NXCOMPAT.",
                evidence="Raw header DllCharacteristics offset"
            ))

    def _scan_strings(self, raw_bytes: bytes, findings: List[SecurityFinding]):
        text = raw_bytes.decode('ascii', errors='ignore')
        for pattern, title, severity, cwe in self.SUSPICIOUS_STRINGS:
            matches = pattern.findall(text)
            if matches:
                sample = str(matches[0])[:60]
                findings.append(SecurityFinding(
                    severity=severity,
                    category="Hardcoded Secrets & Shell Commands",
                    title=title,
                    description=f"Static inspection discovered pattern '{title}' inside executable binary data.",
                    cwe=cwe,
                    remediation="Remove embedded credentials/shell invocations. Inject credentials via secure runtime secret stores.",
                    evidence=sample
                ))
