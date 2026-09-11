import os
import re
import time
import zipfile
import hashlib
import struct
from pathlib import Path
from typing import Dict, Tuple, Optional
from fastapi import HTTPException, status
from .config import settings

class SecurityValidator:
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        base = os.path.basename(filename)
        cleaned = re.sub(r'[^a-zA-Z0-9._-]', '_', base)
        return cleaned or "unnamed_artifact"

    @staticmethod
    def compute_file_hashes(file_path: Path) -> Dict[str, str]:
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)
        return {
            "sha256": sha256.hexdigest(),
            "sha1": sha1.hexdigest(),
            "md5": md5.hexdigest(),
        }

    @staticmethod
    def validate_pe_binary(file_path: Path) -> bool:
        try:
            with open(file_path, "rb") as f:
                header = f.read(64)
                if len(header) < 64 or not header.startswith(b"MZ"):
                    return False
                pe_offset = struct.unpack("<I", header[60:64])[0]
                f.seek(pe_offset)
                pe_sig = f.read(4)
                return pe_sig == b"PE\x00\x00"
        except Exception:
            return False

    @staticmethod
    def validate_apk_package(file_path: Path) -> Tuple[bool, Optional[str]]:
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                if magic != b"PK\x03\x04":
                    return False, "Invalid ZIP archive header"

            total_uncompressed = 0
            total_compressed = 0

            with zipfile.ZipFile(file_path, "r") as zf:
                names = zf.namelist()
                if "AndroidManifest.xml" not in names:
                    return False, "Missing mandatory AndroidManifest.xml"

                for info in zf.infolist():
                    total_uncompressed += info.file_size
                    total_compressed += max(info.compress_size, 1)

                    if total_uncompressed > settings.ZIP_BOMB_MAX_UNCOMPRESSED_BYTES:
                        return False, "Archive exceeds safe decompression bounds (zip bomb defense)"

                ratio = total_uncompressed / max(total_compressed, 1)
                if ratio > settings.ZIP_BOMB_MAX_RATIO and total_uncompressed > 50 * 1024 * 1024:
                    return False, "Excessive compression ratio detected (potential zip bomb)"

            return True, None
        except zipfile.BadZipFile:
            return False, "Corrupted APK or invalid ZIP structure"
        except Exception as e:
            return False, f"APK validation error: {str(e)}"

class InMemoryRateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self.rpm = requests_per_minute
        self.requests: Dict[str, list[float]] = {}

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        window_start = now - 60.0
        records = self.requests.setdefault(client_ip, [])
        self.requests[client_ip] = [t for t in records if t > window_start]
        if len(self.requests[client_ip]) >= self.rpm:
            return False
        self.requests[client_ip].append(now)
        return True

rate_limiter = InMemoryRateLimiter(settings.RATE_LIMIT_REQUESTS_PER_MINUTE)
