// filepath: frontend/src/services/clientAnalyzer.js

function calculateEntropy(bytes) {
  if (!bytes || bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let entropy = 0;
  const len = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      const p = counts[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  return Number(entropy.toFixed(3));
}

async function computeSha256(arrayBuffer) {
  const digest = await crypto.subtle.digest('SHA-256', arrayBuffer);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function decompressDeflateRaw(compressedBytes) {
  try {
    const ds = new DecompressionStream('deflate-raw');
    const writer = ds.writable.getWriter();
    writer.write(compressedBytes);
    writer.close();
    const response = new Response(ds.readable);
    const buffer = await response.arrayBuffer();
    return new Uint8Array(buffer);
  } catch {
    return compressedBytes;
  }
}

function parseZipEntries(buffer) {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const entries = {};
  let offset = 0;

  while (offset + 30 <= bytes.length) {
    const sig = view.getUint32(offset, true);
    if (sig !== 0x04034b50) break;

    const method = view.getUint16(offset + 8, true);
    const compSize = view.getUint32(offset + 18, true);
    const uncompSize = view.getUint32(offset + 22, true);
    const nameLen = view.getUint16(offset + 26, true);
    const extraLen = view.getUint16(offset + 28, true);

    const nameBytes = bytes.subarray(offset + 30, offset + 30 + nameLen);
    const name = new TextDecoder('utf-8').decode(nameBytes);
    const dataStart = offset + 30 + nameLen + extraLen;
    const dataBytes = bytes.subarray(dataStart, dataStart + compSize);

    entries[name] = { method, compSize, uncompSize, dataBytes };
    offset = dataStart + compSize;
  }
  return entries;
}

const PE_DANGEROUS_APIS = [
  'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'WriteProcessMemory',
  'CreateRemoteThread', 'WinExec', 'ShellExecute', 'CreateProcess',
  'IsDebuggerPresent', 'GetAsyncKeyState', 'URLDownloadToFile', 'InternetOpen'
];

export async function analyzeBinaryLocally(file) {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const ext = file.name.split('.').pop().toLowerCase();
  const sha256 = await computeSha256(buffer);

  if (ext === 'exe') {
    return analyzePeLocally(file.name, buffer, bytes, sha256);
  } else if (ext === 'apk') {
    return analyzeApkLocally(file.name, buffer, bytes, sha256);
  } else {
    throw new Error(`Unsupported format .${ext}. Only .apk and .exe are supported.`);
  }
}

function analyzePeLocally(fileName, buffer, bytes, sha256) {
  const view = new DataView(buffer);
  if (view.getUint16(0, true) !== 0x5a4d) {
    throw new Error('Invalid PE binary: missing MZ header.');
  }

  const peOffset = view.getUint32(60, true);
  if (view.getUint32(peOffset, true) !== 0x00004550) {
    throw new Error('Invalid PE binary: missing PE signature.');
  }

  const optHeaderOffset = peOffset + 24;
  const magic = view.getUint16(optHeaderOffset, true);
  const dllCharsOffset = optHeaderOffset + 70;
  const dllChars = view.getUint16(dllCharsOffset, true);

  const aslr = Boolean(dllChars & 0x0040);
  const dep = Boolean(dllChars & 0x0100);
  const cfg = Boolean(dllChars & 0x4000);

  const secDirOffset = optHeaderOffset + (magic === 0x10b ? 96 : 112) + 32;
  const hasSecurityDir = view.getUint32(secDirOffset + 4, true) > 0;

  const findings = [];

  if (!aslr) {
    findings.push({
      severity: 'high',
      category: 'Binary Hardening',
      title: 'Address Space Layout Randomization (ASLR) Disabled',
      description: 'Binary lacks IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE.',
      cwe: 'CWE-119',
      remediation: 'Recompile with /DYNAMICBASE linker flag.'
    });
  }

  if (!dep) {
    findings.push({
      severity: 'critical',
      category: 'Binary Hardening',
      title: 'Data Execution Prevention (DEP / NX) Disabled',
      description: 'Binary lacks NX_COMPAT. Stack and heap pages may be executable.',
      cwe: 'CWE-119',
      remediation: 'Recompile with /NXCOMPAT linker flag.'
    });
  }

  if (!cfg) {
    findings.push({
      severity: 'medium',
      category: 'Binary Hardening',
      title: 'Control Flow Guard (CFG) Inactive',
      description: 'Indirect call targets are not validated.',
      cwe: 'CWE-691',
      remediation: 'Recompile with /guard:cf in MSVC.'
    });
  }

  if (!hasSecurityDir) {
    findings.push({
      severity: 'high',
      category: 'Integrity & Trust',
      title: 'Unsigned Executable Binary',
      description: 'Binary lacks an embedded Authenticode digital signature.',
      cwe: 'CWE-347',
      remediation: 'Sign release binaries with an Authenticode Code Signing Certificate.'
    });
  }

  const text = new TextDecoder('ascii', { fatal: false }).decode(bytes);
  for (const api of PE_DANGEROUS_APIS) {
    if (text.includes(api)) {
      findings.push({
        severity: 'medium',
        category: 'Suspicious API Usage',
        title: `High-Risk API Reference: ${api}`,
        description: `Statically references dynamic execution primitive ${api}.`,
        cwe: 'CWE-250',
        remediation: `Audit callers of ${api} to eliminate unauthorized memory alteration.`
      });
    }
  }

  if (/AKIA[0-9A-Z]{16}/.test(text)) {
    findings.push({
      severity: 'critical',
      category: 'Hardcoded Secrets',
      title: 'AWS Access Key Detected',
      description: 'Hardcoded AWS credential discovered in binary plaintext.',
      cwe: 'CWE-798',
      remediation: 'Extract credentials into secure environment stores or runtime token vaults.'
    });
  }

  const numSections = view.getUint16(peOffset + 6, true);
  const sizeOfOpt = view.getUint16(peOffset + 20, true);
  let sectionOffset = peOffset + 24 + sizeOfOpt;
  const sections = [];

  for (let i = 0; i < Math.min(numSections, 16); i++) {
    const rawName = new TextDecoder('ascii').decode(bytes.subarray(sectionOffset, sectionOffset + 8)).replace(/\0/g, '');
    const rawSize = view.getUint32(sectionOffset + 16, true);
    const rawPtr = view.getUint32(sectionOffset + 20, true);
    if (rawPtr + rawSize <= bytes.length) {
      const entropy = calculateEntropy(bytes.subarray(rawPtr, rawPtr + rawSize));
      sections.push({ name: rawName, entropy, rawSize });
      if (entropy > 7.2) {
        findings.push({
          severity: 'medium',
          category: 'Packer & Obfuscation',
          title: `High Section Entropy (${rawName}: ${entropy})`,
          description: `Section ${rawName} shows entropy > 7.2, indicating packed or encrypted payload.`,
          cwe: 'CWE-506',
          remediation: 'Inspect for unauthorized binary obfuscation or encrypted stubs.'
        });
      }
    }
    sectionOffset += 40;
  }

  return buildStandardReport(fileName, 'EXE', bytes.length, sha256, findings, {
    format: magic === 0x10b ? 'PE32 (x86)' : 'PE32+ (x64)',
    aslr,
    dep,
    is_signed: hasSecurityDir,
    sections_count: numSections
  });
}

async function analyzeApkLocally(fileName, buffer, bytes, sha256) {
  const entries = parseZipEntries(buffer);
  if (!entries['AndroidManifest.xml']) {
    throw new Error('Invalid APK: missing AndroidManifest.xml.');
  }

  const findings = [];
  let manifestText = '';

  const manifestEntry = entries['AndroidManifest.xml'];
  let rawManifest = manifestEntry.dataBytes;
  if (manifestEntry.method === 8) {
    rawManifest = await decompressDeflateRaw(rawManifest);
  }
  manifestText = new TextDecoder('utf-8', { fatal: false }).decode(rawManifest);

  if (/debuggable/i.test(manifestText) && /(?:debuggable\s*=\s*["']?true["']?|\x01)/i.test(manifestText)) {
    findings.push({
      severity: 'critical',
      category: 'Manifest Security',
      title: 'Application is Debuggable in Release Mode',
      description: 'android:debuggable="true" permits arbitrary code execution via jdb.',
      cwe: 'CWE-215',
      remediation: 'Set android:debuggable="false" in production builds.'
    });
  }

  if (/usescleartexttraffic/i.test(manifestText) && /(?:usesCleartextTraffic\s*=\s*["']?true["']?|\x01)/i.test(manifestText)) {
    findings.push({
      severity: 'high',
      category: 'Network Security',
      title: 'Cleartext HTTP Traffic Permitted',
      description: 'android:usesCleartextTraffic="true" exposes traffic to MitM sniffing.',
      cwe: 'CWE-319',
      remediation: 'Enforce android:usesCleartextTraffic="false" and mandate TLS.'
    });
  }

  if (/allowbackup/i.test(manifestText) && /(?:allowBackup\s*=\s*["']?true["']?|\x01)/i.test(manifestText)) {
    findings.push({
      severity: 'medium',
      category: 'Data Storage',
      title: 'Application Backup Enabled (ADB Data Leak)',
      description: 'android:allowBackup="true" permits database extraction via ADB.',
      cwe: 'CWE-921',
      remediation: 'Set android:allowBackup="false" in AndroidManifest.xml.'
    });
  }

  const dangerousPerms = [
    ['android.permission.RECORD_AUDIO', 'Microphone Eavesdropping', 'medium'],
    ['android.permission.CAMERA', 'Camera Access', 'medium'],
    ['android.permission.ACCESS_FINE_LOCATION', 'GPS Tracking', 'medium'],
    ['android.permission.READ_SMS', 'SMS Reading', 'high'],
    ['android.permission.SEND_SMS', 'SMS Manipulation', 'high'],
    ['android.permission.SYSTEM_ALERT_WINDOW', 'Overlay Hijacking', 'high']
  ];

  for (const [perm, title, sev] of dangerousPerms) {
    if (manifestText.includes(perm) || manifestText.includes(perm.split('.').pop())) {
      findings.push({
        severity: sev,
        category: 'Dangerous Permissions',
        title: `Excessive Permission: ${perm.split('.').pop()}`,
        description: `App requests ${perm} (${title}).`,
        cwe: 'CWE-250',
        remediation: 'Audit necessity and replace with scoped runtime intents.'
      });
    }
  }

  let hasSignature = false;
  let isDebugKeystore = false;
  for (const name of Object.keys(entries)) {
    if (name.startsWith('META-INF/') && (name.endsWith('.RSA') || name.endsWith('.DSA') || name.endsWith('.EC'))) {
      hasSignature = true;
      const certStr = new TextDecoder('latin1').decode(entries[name].dataBytes);
      if (certStr.includes('Android Debug') || certStr.includes('debug.keystore')) {
        isDebugKeystore = true;
      }
    }
  }

  if (!hasSignature) {
    findings.push({
      severity: 'critical',
      category: 'Code Integrity',
      title: 'Unsigned APK Package',
      description: 'Missing valid META-INF signature file.',
      cwe: 'CWE-347',
      remediation: 'Sign the APK with a production release keystore using apksigner.'
    });
  } else if (isDebugKeystore) {
    findings.push({
      severity: 'critical',
      category: 'Code Integrity',
      title: 'Signed with Insecure Android Debug Keystore',
      description: 'Signed with default public debug keystore (CN=Android Debug).',
      cwe: 'CWE-295',
      remediation: 'Re-sign with a secure, password-protected production release keystore.'
    });
  }

  const dexEntries = Object.keys(entries).filter(n => n.endsWith('.dex'));
  for (const dexName of dexEntries) {
    let dexData = entries[dexName].dataBytes;
    if (entries[dexName].method === 8) {
      dexData = await decompressDeflateRaw(dexData);
    }
    const dexText = new TextDecoder('ascii', { fatal: false }).decode(dexData);
    if (/AKIA[0-9A-Z]{16}/.test(dexText)) {
      findings.push({
        severity: 'critical',
        category: 'Hardcoded Secrets',
        title: `AWS Access Key Detected in ${dexName}`,
        description: 'Hardcoded AWS credential pattern in compiled DEX bytecode.',
        cwe: 'CWE-798',
        remediation: 'Remove credentials from bytecode. Use backend proxy.'
      });
    }
    if (/AIza[0-9A-Za-z-_]{35}/.test(dexText)) {
      findings.push({
        severity: 'high',
        category: 'Hardcoded Secrets',
        title: `Google API Key Detected in ${dexName}`,
        description: 'Google API key embedded in DEX bytecode.',
        cwe: 'CWE-798',
        remediation: 'Restrict key by package name/SHA-1 fingerprint in Google Cloud Console.'
      });
    }
  }

  return buildStandardReport(fileName, 'APK', bytes.length, sha256, findings, {
    format: 'Android Package (APK)',
    dex_files: dexEntries.length,
    is_signed: hasSignature && !isDebugKeystore
  });
}

function buildStandardReport(fileName, fileType, fileSize, sha256, findings, staticInfo) {
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;

  let rawScore = 1.0;
  for (const f of findings) {
    if (f.severity === 'critical') rawScore += 2.8;
    else if (f.severity === 'high') rawScore += 1.6;
    else if (f.severity === 'medium') rawScore += 0.7;
    else rawScore += 0.2;
  }
  const hackabilityScore = Number(Math.min(10.0, Math.max(1.0, rawScore)).toFixed(1));

  const improvements = Array.from(new Set(findings.map(f => f.remediation))).slice(0, 8);
  if (improvements.length === 0) {
    improvements.push('Maintain automated SAST scanning in your CI/CD pipeline.');
    improvements.push('Enforce cryptographic signature verification across releases.');
  }

  const fixPrompt = `Act as a Staff Security Engineer. Generate remediation patches for ${fileName}:\n` +
    findings.map(f => `- [${f.severity.toUpperCase()}] ${f.title}: ${f.remediation}`).join('\n');

  const bugs = findings.filter(f => ['medium', 'low', 'info'].includes(f.severity));
  const securityFindings = findings.filter(f => ['critical', 'high'].includes(f.severity));

  return {
    reportId: `local-${Date.now()}`,
    fileName,
    fileType,
    fileSize,
    hackabilityScore,
    criticalCount,
    bugCount: bugs.length,
    bugs,
    securityFindings,
    improvements,
    aiSummary: `Local client-side inspection completed for ${fileName}. Hackability Score: ${hackabilityScore}/10 with ${criticalCount} critical and ${highCount} high severity issues.`,
    fixPrompt,
    staticInfo: {
      sha256,
      ...staticInfo
    },
    sandboxResults: {
      status: 'completed',
      logs: [
        `Local in-browser client analysis complete for ${fileName}.`,
        `100% private: File was analyzed in-browser without network transmission.`,
        `Assessed ${findings.length} security parameters.`
      ]
    }
  };
}
