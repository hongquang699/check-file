#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Virus & Hidden Files / Folders Scanner
Features:
1. Scan download URLs or local file/folder paths.
2. Detect hidden files and directories (including inside ZIP/TAR archives).
3. Detect double extensions and disguised executables via Magic Bytes.
4. Scan with native Windows Defender (Offline).
5. Query VirusTotal API using SHA256 file hashes (Online).
"""

import os
import sys
import re

# Configure UTF-8 encoding for Windows Terminal to support Unicode characters
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import time
import shutil
import hashlib
import tempfile
import subprocess
import urllib.request
import urllib.parse
import zipfile
import tarfile
from pathlib import Path

# Configuration file for storing settings such as API Keys
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# Dangerous file extensions commonly used to distribute malware
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".scr", ".pif", ".hta", ".cpl", ".msc", ".jar", ".lnk", ".iso", ".img", ".dll",
    ".sys", ".com", ".reg", ".msi", ".msp"
}

# Image extensions supported for deep steganography & payload inspection
IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tiff", ".tif", ".svg", ".psd"
}

# Magic bytes to identify headers
PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"
ZIP_MAGIC = b"PK\x03\x04"
RAR_MAGIC = b"Rar!\x1a\x07"
SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
PDF_MAGIC = b"%PDF"

# Image Magic Bytes
JPEG_MAGIC = b"\xff\xd8\xff"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
GIF87_MAGIC = b"GIF87a"
GIF89_MAGIC = b"GIF89a"
BMP_MAGIC = b"BM"
WEBP_MAGIC = b"RIFF"

# Source code file extensions for IT project security scanning
CODE_EXTENSIONS = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".php", ".phtml", ".java", ".jsp", ".go", ".rb", ".rs", ".c",
    ".cpp", ".h", ".hpp", ".cs", ".kt", ".swift", ".scala", ".sh",
    ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".sql", ".env", ".json",
    ".yml", ".yaml", ".xml", ".toml", ".ini", ".conf", ".config", ".html"
}

# Directories to exclude during codebase scan (libraries, caches, venvs)
EXCLUDED_CODE_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv", "env",
    "vendor", "dist", "build", ".idea", ".vscode", "bin", "obj",
    "target", ".next", ".nuxt", "coverage", ".pytest_cache", ".tox"
}


class Colors:
    """Terminal color formatting using ANSI escape codes"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def init(cls):
        # Enable ANSI colors on Windows Terminal / Command Prompt
        if sys.platform == "win32":
            os.system("")


def print_banner():
    Colors.init()
    banner = f"""
{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════════════╗
║               VIRUS & HIDDEN FILES / FOLDERS SCANNER                 ║
║               (Download URLs / Local Files & Archives)               ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def load_config():
    """Load configuration from config.json"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_config(config):
    """Save configuration to config.json"""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Failed to save configuration: {e}{Colors.RESET}")


def calculate_hashes(file_path):
    """Calculate MD5, SHA1, and SHA256 hashes of a file"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def download_file(url, target_dir):
    """Download a remote file from URL to a temporary directory with a progress bar"""
    print(f"{Colors.BLUE}[*] Connecting to URL:{Colors.RESET} {url}")
    parsed = urllib.parse.urlparse(url)
    filename = os.path.basename(parsed.path)
    if not filename or filename == "/":
        filename = f"downloaded_file_{int(time.time())}"

    dest_path = os.path.join(target_dir, filename)

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            )
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response, open(dest_path, "wb") as out_file:
            content_length = response.headers.get("Content-Length")
            total_size = int(content_length) if content_length else None
            downloaded = 0
            block_size = 65536

            while True:
                buffer = response.read(block_size)
                if not buffer:
                    break
                out_file.write(buffer)
                downloaded += len(buffer)
                if total_size:
                    percent = downloaded * 100 / total_size
                    bar = ("=" * int(percent // 4)).ljust(25)
                    sys.stdout.write(f"\r{Colors.CYAN}[*] Downloading: [{bar}] {percent:.1f}% ({downloaded/(1024*1024):.2f} MB){Colors.RESET}")
                    sys.stdout.flush()
                else:
                    sys.stdout.write(f"\r{Colors.CYAN}[*] Downloaded: {downloaded/(1024*1024):.2f} MB{Colors.RESET}")
                    sys.stdout.flush()

        print(f"\n{Colors.GREEN}[✓] Download completed: {os.path.basename(dest_path)}{Colors.RESET}")
        return dest_path
    except Exception as e:
        print(f"\n{Colors.RED}[✗] Error downloading file from URL: {e}{Colors.RESET}")
        return None


def is_windows_hidden(file_path):
    """Check if file or directory has Windows Hidden or System attributes"""
    if sys.platform == "win32":
        try:
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(file_path))
            if attrs != -1:
                # FILE_ATTRIBUTE_HIDDEN = 0x02, FILE_ATTRIBUTE_SYSTEM = 0x04
                return bool(attrs & 2 or attrs & 4)
        except Exception:
            pass
    name = os.path.basename(file_path)
    return name.startswith(".")


def analyze_file_extension(file_path):
    """Deep analysis of full filename, real extension, hidden extension, RLO, and space padding"""
    name = os.path.basename(file_path)
    
    # 1. RLO character detection (Right-to-Left Override \u202E, \u202B, \u202D, \u202A, \u202C)
    has_rlo = any(char in name for char in ["\u202e", "\u202b", "\u202d", "\u202a", "\u202c"])
    
    # 2. Check for space padding before extension (e.g. "invoice.pdf          .exe")
    has_space_padding = bool(re.search(r'\s{3,}\.[a-zA-Z0-9]+$', name))
    
    # 3. Clean filename and parse all extensions
    clean_name = re.sub(r'[\u202a-\u202e]', '', name)
    parts = clean_name.split(".")
    
    real_ext = f".{parts[-1].lower()}" if len(parts) > 1 else "(No extension)"
    fake_ext = f".{parts[-2].lower()}" if len(parts) > 2 else ""
    is_double_ext = len(parts) > 2 and (f".{parts[-1].lower()}" in DANGEROUS_EXTENSIONS)
    
    # 4. Binary magic header check
    magic_type = "Generic File / Unknown"
    magic_mismatch = False
    try:
        with open(file_path, "rb") as f:
            header = f.read(32)
        if header.startswith(PE_MAGIC):
            magic_type = "Windows PE Executable (EXE/DLL)"
            if real_ext not in {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".msi"}:
                magic_mismatch = True
        elif header.startswith(ELF_MAGIC):
            magic_type = "Linux ELF Executable"
            if real_ext not in {".elf", ".bin", ""}:
                magic_mismatch = True
        elif header.startswith(PDF_MAGIC):
            magic_type = "Adobe PDF Document"
        elif header.startswith(JPEG_MAGIC):
            magic_type = "JPEG Image"
        elif header.startswith(PNG_MAGIC):
            magic_type = "PNG Image"
        elif header.startswith(GIF87_MAGIC) or header.startswith(GIF89_MAGIC):
            magic_type = "GIF Image"
        elif header.startswith(ZIP_MAGIC):
            magic_type = "ZIP / OpenXML Archive"
        elif header.startswith(RAR_MAGIC):
            magic_type = "RAR Archive"
    except Exception:
        pass

    return {
        "full_name": name,
        "clean_name": clean_name,
        "real_ext": real_ext,
        "fake_ext": fake_ext,
        "is_double_ext": is_double_ext,
        "has_rlo": has_rlo,
        "has_space_padding": has_space_padding,
        "magic_type": magic_type,
        "magic_mismatch": magic_mismatch
    }


def check_disguised_file(file_path):
    """Check if file has double extensions, RLO spoofing, space padding, or disguised headers"""
    suspicious_reports = []
    ext_info = analyze_file_extension(file_path)

    if ext_info["has_rlo"]:
        suspicious_reports.append(
            "CRITICAL: Right-to-Left Override (RLO) character detected! The file extension is reversed to deceive Windows users."
        )

    if ext_info["has_space_padding"]:
        suspicious_reports.append(
            "CRITICAL: Space padding detected before the extension to hide the real executable extension off-screen."
        )

    if ext_info["is_double_ext"]:
        suspicious_reports.append(
            f"Dangerous double extension: Apparent extension '{ext_info['fake_ext']}' vs Real executable extension '{ext_info['real_ext']}'!"
        )

    if ext_info["magic_mismatch"]:
        suspicious_reports.append(
            f"Extension Mismatch: True binary format is '{ext_info['magic_type']}' but file claims extension '{ext_info['real_ext']}'!"
        )

    return suspicious_reports


def scan_archive_contents(archive_path):
    """Inspect archive structure (ZIP/TAR) for hidden items and dangerous files without extracting"""
    results = {
        "hidden_files": [],
        "hidden_dirs": [],
        "suspicious_files": [],
        "all_entries_count": 0
    }

    # Inspect ZIP archives
    if zipfile.is_zipfile(archive_path):
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                infolist = zf.infolist()
                results["all_entries_count"] = len(infolist)

                for item in infolist:
                    filename = item.filename
                    parts = [p for p in filename.replace("\\", "/").split("/") if p]
                    
                    # Detect hidden items (leading dot)
                    for i, part in enumerate(parts):
                        if part.startswith("."):
                            if i == len(parts) - 1 and not item.is_dir():
                                results["hidden_files"].append(filename)
                            else:
                                results["hidden_dirs"].append("/".join(parts[:i+1]))
                            break

                    # Check for dangerous extensions inside the archive
                    if not item.is_dir():
                        ext = os.path.splitext(filename.lower())[1]
                        if ext in DANGEROUS_EXTENSIONS:
                            results["suspicious_files"].append(f"{filename} (Dangerous executable extension: {ext})")
                        
                        # Check for double extensions
                        base_parts = os.path.basename(filename).split(".")
                        if len(base_parts) > 2:
                            last_ext = f".{base_parts[-1].lower()}"
                            if last_ext in DANGEROUS_EXTENSIONS:
                                results["suspicious_files"].append(f"{filename} (Double extension: .{base_parts[-2]}{last_ext})")

        except Exception as e:
            results["error"] = f"Failed to read ZIP archive: {e}"

    # Inspect TAR archives
    elif tarfile.is_tarfile(archive_path):
        try:
            with tarfile.open(archive_path, "r:*") as tf:
                members = tf.getmembers()
                results["all_entries_count"] = len(members)

                for m in members:
                    filename = m.name
                    parts = [p for p in filename.replace("\\", "/").split("/") if p]
                    for i, part in enumerate(parts):
                        if part.startswith("."):
                            if m.isdir():
                                results["hidden_dirs"].append("/".join(parts[:i+1]))
                            else:
                                results["hidden_files"].append(filename)
                            break

                    if not m.isdir():
                        ext = os.path.splitext(filename.lower())[1]
                        if ext in DANGEROUS_EXTENSIONS:
                            results["suspicious_files"].append(f"{filename} (Dangerous executable extension: {ext})")
        except Exception as e:
            results["error"] = f"Failed to read TAR archive: {e}"

    return results


def scan_directory_hidden(dir_path):
    """Scan a local directory for hidden files, hidden folders, and suspicious files"""
    results = {
        "hidden_files": [],
        "hidden_dirs": [],
        "suspicious_files": [],
        "total_files": 0,
        "total_dirs": 0
    }

    for root, dirs, files in os.walk(dir_path):
        results["total_dirs"] += len(dirs)
        results["total_files"] += len(files)

        # Check for hidden directories
        for d in dirs:
            full_d = os.path.join(root, d)
            if is_windows_hidden(full_d) or d.startswith("."):
                rel_path = os.path.relpath(full_d, dir_path)
                results["hidden_dirs"].append(rel_path)

        # Check for hidden files & disguised/suspicious files
        for f in files:
            full_f = os.path.join(root, f)
            rel_f = os.path.relpath(full_f, dir_path)

            if is_windows_hidden(full_f) or f.startswith("."):
                results["hidden_files"].append(rel_f)

            disguises = check_disguised_file(full_f)
            if disguises:
                for d in disguises:
                    results["suspicious_files"].append(f"{rel_f} - {d}")
            else:
                ext = os.path.splitext(f.lower())[1]
                if ext in DANGEROUS_EXTENSIONS:
                    results["suspicious_files"].append(f"{rel_f} (Executable format: {ext})")

    return results


def scan_with_windows_defender(target_path):
    """Run native Windows Defender command-line scanner (MpCmdRun.exe)"""
    if sys.platform != "win32":
        return {"supported": False, "message": "Only available on Windows OS"}

    defender_paths = [
        r"C:\Program Files\Windows Defender\MpCmdRun.exe",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform",
    ]

    exe_path = None
    if os.path.exists(defender_paths[0]):
        exe_path = defender_paths[0]
    elif os.path.exists(defender_paths[1]):
        try:
            for sub in sorted(os.listdir(defender_paths[1]), reverse=True):
                candidate = os.path.join(defender_paths[1], sub, "MpCmdRun.exe")
                if os.path.exists(candidate):
                    exe_path = candidate
                    break
        except Exception:
            pass

    if not exe_path:
        return {"supported": False, "message": "Windows Defender executable (MpCmdRun.exe) not found"}

    cmd = [exe_path, "-Scan", "-ScanType", "3", "-File", target_path, "-DisableRemediation"]
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = (process.stdout or "") + (process.stderr or "")
        
        # MpCmdRun exit codes: 0 = No threats, 2 = Threat found
        if process.returncode == 0:
            return {"supported": True, "clean": True, "message": "Windows Defender detected no threats."}
        elif process.returncode == 2:
            return {"supported": True, "clean": False, "message": "THREAT / MALWARE DETECTED!", "details": output}
        else:
            if "no threats" in output.lower():
                return {"supported": True, "clean": True, "message": "Windows Defender detected no threats."}
            return {"supported": True, "clean": None, "message": f"Scan result: {output.strip()[:200]}"}
    except subprocess.TimeoutExpired:
        return {"supported": True, "clean": None, "message": "Windows Defender scan timed out."}
    except Exception as e:
        return {"supported": False, "message": f"Windows Defender execution error: {e}"}


def check_virustotal(sha256_hash, api_key=None):
    """Query VirusTotal v3 API using SHA256 hash"""
    vt_url = f"https://www.virustotal.com/gui/file/{sha256_hash}"

    if not api_key:
        return {
            "has_api": False,
            "vt_url": vt_url,
            "message": "No API Key configured. You can view the live report via the VirusTotal link below."
        }

    api_endpoint = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    req = urllib.request.Request(
        api_endpoint,
        headers={
            "x-apikey": api_key,
            "User-Agent": "VirusCheckScript/1.0"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            detections = []
            for engine, info in results.items():
                category = info.get("category")
                if category in ("malicious", "suspicious"):
                    detections.append(f"{engine}: {info.get('result', 'Malware')}")

            return {
                "has_api": True,
                "found": True,
                "vt_url": vt_url,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total": malicious + suspicious + harmless + undetected,
                "detections": detections[:10],
                "reputation": attributes.get("reputation", 0)
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "has_api": True,
                "found": False,
                "vt_url": vt_url,
                "message": "File has not been analyzed or submitted to VirusTotal yet."
            }
        elif e.code == 401:
            return {
                "has_api": True,
                "error": "Invalid or expired VirusTotal API Key.",
                "vt_url": vt_url
            }
        else:
            return {
                "has_api": True,
                "error": f"HTTP Error {e.code}: {e.reason}",
                "vt_url": vt_url
            }
    except Exception as e:
        return {
            "has_api": True,
            "error": f"VirusTotal connection error: {e}",
            "vt_url": vt_url
        }


def scan_image_security(file_path):
    """Deep security analysis for image files (Steganography, embedded payloads, SVG XSS, polyglots)"""
    ext = os.path.splitext(file_path.lower())[1]
    is_img = ext in IMAGE_EXTENSIONS

    try:
        with open(file_path, "rb") as f:
            header_sample = f.read(32)
        if (header_sample.startswith(JPEG_MAGIC) or header_sample.startswith(PNG_MAGIC) or
            header_sample.startswith(GIF87_MAGIC) or header_sample.startswith(GIF89_MAGIC) or
            header_sample.startswith(BMP_MAGIC) or (header_sample.startswith(b"RIFF") and b"WEBP" in header_sample) or
            b"<svg" in header_sample.lower()):
            is_img = True
    except Exception:
        pass

    if not is_img:
        return None

    results = {
        "is_image": True,
        "format_detected": "Unknown Image Format",
        "threats": [],
        "warnings": [],
        "details": []
    }

    try:
        with open(file_path, "rb") as f:
            content = f.read()
        
        file_size = len(content)

        # 1. Format Detection & Trailing payload checks (Steganography)
        if content.startswith(JPEG_MAGIC):
            results["format_detected"] = "JPEG / JPG"
            eoi_index = content.rfind(b"\xff\xd9")
            if eoi_index != -1 and (file_size - (eoi_index + 2)) > 64:
                trailing_size = file_size - (eoi_index + 2)
                results["warnings"].append(
                    f"Detected {trailing_size} bytes of trailing data after JPEG EOI marker (Possible hidden steganography payload / appended data)."
                )

        elif content.startswith(PNG_MAGIC):
            results["format_detected"] = "PNG"
            iend_index = content.rfind(b"IEND")
            if iend_index != -1 and (file_size - (iend_index + 8)) > 64:
                trailing_size = file_size - (iend_index + 8)
                results["warnings"].append(
                    f"Detected {trailing_size} bytes of trailing data after PNG IEND chunk (Possible hidden payload)."
                )

        elif content.startswith(GIF87_MAGIC) or content.startswith(GIF89_MAGIC):
            results["format_detected"] = "GIF"
            trailer_index = content.rfind(b"\x3b")
            if trailer_index != -1 and (file_size - (trailer_index + 1)) > 64:
                trailing_size = file_size - (trailer_index + 1)
                results["warnings"].append(
                    f"Detected {trailing_size} bytes of trailing data after GIF trailer (Possible hidden payload)."
                )

        elif content.startswith(BMP_MAGIC):
            results["format_detected"] = "BMP"

        elif content.startswith(b"RIFF") and b"WEBP" in content[:16]:
            results["format_detected"] = "WEBP"

        elif ext == ".svg" or b"<svg" in content[:1024].lower():
            results["format_detected"] = "SVG (Vector Graphics)"
            svg_text = content.decode("utf-8", errors="ignore").lower()
            
            dangerous_svg_patterns = [
                ("<script", "Embedded JavaScript <script> tag (Cross-Site Scripting XSS risk)"),
                ("javascript:", "JavaScript URI scheme detected (XSS risk)"),
                ("onload=", "Malicious event handler (onload) detected"),
                ("onerror=", "Malicious event handler (onerror) detected"),
                ("onclick=", "Event handler (onclick) detected"),
                ("<iframe", "Embedded <iframe> tag detected"),
                ("<!entity", "XML External Entity (XXE) entity declaration detected"),
                ("system ", "XML External Entity SYSTEM identifier detected"),
            ]
            for pattern, desc in dangerous_svg_patterns:
                if pattern in svg_text:
                    results["threats"].append(desc)

        # 2. Polyglot & Embedded Executable / Archive inside Image
        pe_pos = content.find(b"MZ", 64)
        if pe_pos != -1 and pe_pos < file_size - 128:
            if b"PE\x00\x00" in content[pe_pos:pe_pos+1024]:
                results["threats"].append(f"Embedded Windows Executable (PE/MZ) binary found at byte offset {pe_pos} (Polyglot malware)!")

        elf_pos = content.find(b"\x7fELF", 16)
        if elf_pos != -1:
            results["threats"].append(f"Embedded Linux ELF executable found at byte offset {elf_pos}!")

        zip_pos = content.find(b"PK\x03\x04", 16)
        if zip_pos != -1:
            results["warnings"].append(f"Embedded ZIP archive detected inside image at byte offset {zip_pos} (Polyglot / RarJPEG-style archive).")

        rar_pos = content.find(b"Rar!\x1a\x07", 16)
        if rar_pos != -1:
            results["warnings"].append(f"Embedded RAR archive detected inside image at byte offset {rar_pos} (RarJPEG).")

        # 3. Check for embedded WebShell / Script signatures
        lower_content = content.lower()
        script_indicators = [
            (b"<?php", "Embedded PHP code / WebShell indicator"),
            (b"eval(", "Embedded eval() execution function"),
            (b"base64_decode(", "Embedded base64_decode execution function"),
            (b"powershell", "Embedded PowerShell command string"),
            (b"cmd.exe", "Embedded cmd.exe command string"),
            (b"wscript.shell", "Embedded Windows Script Host (WScript.Shell)"),
            (b"passthru(", "Embedded PHP passthru() function"),
            (b"shell_exec(", "Embedded PHP shell_exec() function")
        ]
        for ind, desc in script_indicators:
            if ind in lower_content:
                results["threats"].append(f"{desc} (Found matching pattern '{ind.decode('ascii', errors='ignore')}')")

    except Exception as e:
        results["warnings"].append(f"Could not complete image security scan: {e}")

    return results


def mask_secret(secret_str):
    """Mask sensitive secret strings for safe display in reports"""
    if len(secret_str) <= 8:
        return "****"
    return secret_str[:4] + "*" * (len(secret_str) - 8) + secret_str[-4:]


# Security rules for IT Codebase Static Analysis (SAST & Secret Scanning)
CODEBASE_RULES = [
    # 1. Leaked Secrets & API Keys (CRITICAL)
    {
        "id": "SEC001",
        "category": "LEAKED_SECRET",
        "severity": "CRITICAL",
        "title": "AWS Access Key ID Leaked",
        "pattern": r'\b(AKIA[0-9A-Z]{16})\b',
        "description": "Hardcoded AWS Access Key ID exposes cloud infrastructure to unauthorized access.",
        "recommendation": "Remove from source code and load from environment variables (e.g. AWS_ACCESS_KEY_ID)."
    },
    {
        "id": "SEC002",
        "category": "LEAKED_SECRET",
        "severity": "CRITICAL",
        "title": "GitHub Token Leaked",
        "pattern": r'\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{82})\b',
        "description": "Hardcoded GitHub Personal Access Token can grant full repository access.",
        "recommendation": "Revoke the token immediately on GitHub and use .env / environment variables."
    },
    {
        "id": "SEC003",
        "category": "LEAKED_SECRET",
        "severity": "CRITICAL",
        "title": "Google Cloud / Maps API Key",
        "pattern": r'\b(AIza[0-9A-Za-z\-_]{35})\b',
        "description": "Hardcoded Google API key can lead to quota exhaustion and financial loss.",
        "recommendation": "Restrict key usage in Google Cloud Console and load from environment variables."
    },
    {
        "id": "SEC004",
        "category": "LEAKED_SECRET",
        "severity": "CRITICAL",
        "title": "OpenAI / Anthropic API Key",
        "pattern": r'\b(sk-[a-zA-Z0-9]{32,}|sk-ant-[a-zA-Z0-9_\-]{40,})\b',
        "description": "Hardcoded AI API key can cause billing abuse.",
        "recommendation": "Store in .env and access via os.environ['OPENAI_API_KEY']."
    },
    {
        "id": "SEC005",
        "category": "LEAKED_SECRET",
        "severity": "CRITICAL",
        "title": "Stripe API Key",
        "pattern": r'\b((?:sk_live|rk_live)_[0-9a-zA-Z]{20,})\b',
        "description": "Live Stripe Secret Key exposes financial transactions and customer data.",
        "recommendation": "Never commit live payment keys to version control."
    },
    {
        "id": "SEC006",
        "category": "LEAKED_SECRET",
        "severity": "CRITICAL",
        "title": "Private Cryptographic Key",
        "pattern": r'-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----',
        "description": "Private SSH/SSL/TLS key committed in plaintext.",
        "recommendation": "Store private keys in a secure key vault or SSH agent, never in source code."
    },
    {
        "id": "SEC007",
        "category": "LEAKED_SECRET",
        "severity": "CRITICAL",
        "title": "Database Connection String with Credentials",
        "pattern": r'(?i)\b(?:mongodb(?:\+srv)?|postgresql|postgres|mysql|redis|amqp):\/\/[a-zA-Z0-9_.\-%]+:[a-zA-Z0-9_.\-%@!#$^&*]+@[a-zA-Z0-9_.\-]+',
        "description": "Database URI contains hardcoded username and password.",
        "recommendation": "Use DATABASE_URL from environment variables."
    },
    {
        "id": "SEC008",
        "category": "LEAKED_SECRET",
        "severity": "HIGH",
        "title": "Generic Hardcoded Secret / Password Assignment",
        "pattern": r'(?i)\b(?:password|secret_key|api_secret|auth_token|jwt_secret)\s*=\s*[\'"][a-zA-Z0-9@#$%^&*()_+=\-!]{8,64}[\'"]',
        "description": "Hardcoded credential string in variable assignment.",
        "recommendation": "Replace hardcoded value with environment configuration."
    },

    # 2. Command Injection & Remote Code Execution (HIGH)
    {
        "id": "VULN001",
        "category": "COMMAND_INJECTION",
        "severity": "HIGH",
        "title": "Dynamic Code Execution (eval / exec)",
        "pattern": r'(?<![\'"])\b(?:eval|exec)\s*\([^)]+\)',
        "description": "eval() and exec() execute arbitrary strings as code, leading to Remote Code Execution (RCE).",
        "recommendation": "Refactor logic to use safe parsing (e.g. ast.literal_eval, json.loads)."
    },
    {
        "id": "VULN002",
        "category": "COMMAND_INJECTION",
        "severity": "HIGH",
        "title": "Insecure Subprocess Execution (shell=True)",
        "pattern": r'subprocess\.(?:Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True',
        "description": "Executing system commands with shell=True is vulnerable to command injection.",
        "recommendation": "Pass command arguments as a list and set shell=False."
    },
    {
        "id": "VULN003",
        "category": "COMMAND_INJECTION",
        "severity": "HIGH",
        "title": "OS Shell Command Execution",
        "pattern": r'\bos\.(?:system|popen)\s*\(\s*(?!["\'](?:["\']|\s*["\']))[^)]+\)',
        "description": "os.system executes commands via shell and does not sanitize user inputs.",
        "recommendation": "Use subprocess.run with argument list instead of raw shell strings."
    },
    {
        "id": "VULN004",
        "category": "COMMAND_INJECTION",
        "severity": "HIGH",
        "title": "PHP Dangerous Execution Function",
        "target_extensions": {".php", ".phtml", ".inc"},
        "pattern": r'\b(?:system|passthru|shell_exec|exec|popen|proc_open)\s*\([^)]+\)',
        "description": "PHP shell execution functions can result in server compromise.",
        "recommendation": "Avoid invoking system commands or use escapeshellarg() / escapeshellcmd()."
    },

    # 3. SQL Injection (HIGH)
    {
        "id": "VULN005",
        "category": "SQL_INJECTION",
        "severity": "HIGH",
        "title": "Potential SQL Injection (String Interpolation in SQL)",
        "pattern": r'(?i)\b(?:SELECT\s+[\w\s,*]+\s+FROM|INSERT\s+INTO\s+\w+|UPDATE\s+\w+\s+SET|DELETE\s+FROM\s+\w+)\s+[^;\'"]*(?:%s|\{\}|\.format\s*\(|\+\s*[a-zA-Z_]|\$\{[a-zA-Z_])',
        "description": "Constructing SQL queries via string concatenation allows SQL Injection.",
        "recommendation": "Use parameterized queries / prepared statements (e.g. cursor.execute('SELECT * WHERE id = ?', (id,)))."
    },
    {
        "id": "VULN006",
        "category": "SQL_INJECTION",
        "severity": "HIGH",
        "title": "Python f-string SQL Query",
        "pattern": r'(?i)f[\'"][^\'"]*\b(?:SELECT\s+[\w\s,*]+\s+FROM|INSERT\s+INTO\s+\w+|UPDATE\s+\w+\s+SET|DELETE\s+FROM\s+\w+)\s+.*\{[a-zA-Z_]',
        "description": "Using Python f-strings in SQL queries bypasses query parameterization.",
        "recommendation": "Use ORM or parameterized query binding."
    },

    # 4. Insecure Deserialization (HIGH)
    {
        "id": "VULN007",
        "category": "INSECURE_DESERIALIZATION",
        "severity": "HIGH",
        "title": "Insecure Python Pickle Deserialization",
        "target_extensions": {".py", ".pyw"},
        "pattern": r'\bpickle\.(?:loads?|load)\s*\([^)]*\)',
        "description": "Unpickling untrusted data allows arbitrary code execution.",
        "recommendation": "Use safe data formats like JSON, MessagePack, or Protocol Buffers."
    },
    {
        "id": "VULN008",
        "category": "INSECURE_DESERIALIZATION",
        "severity": "HIGH",
        "title": "Unsafe YAML Deserialization",
        "target_extensions": {".py", ".pyw"},
        "pattern": r'\byaml\.(?:load|unsafe_load)\s*\([^)]*(?:Loader\s*=\s*yaml\.(?:UnsafeLoader|Loader)|[^\w]Loader\b)',
        "description": "yaml.load with default or UnsafeLoader can execute arbitrary Python objects.",
        "recommendation": "Use yaml.safe_load(data) instead."
    },

    # 5. Weak Cryptography (MEDIUM)
    {
        "id": "VULN009",
        "category": "WEAK_CRYPTOGRAPHY",
        "severity": "MEDIUM",
        "title": "Weak Hash Algorithm (MD5 / SHA1 for Security)",
        "pattern": r'\bhashlib\.(?:md5|sha1)\s*\([^)]*\)',
        "description": "MD5 and SHA1 are cryptographically broken and vulnerable to collision attacks.",
        "recommendation": "Use SHA-256 (hashlib.sha256) or bcrypt/argon2 for password hashing."
    },

    # 6. Web / API Security Issues (MEDIUM)
    {
        "id": "VULN010",
        "category": "XSS_VULNERABILITY",
        "severity": "MEDIUM",
        "title": "React DangerouslySetInnerHTML XSS",
        "target_extensions": {".js", ".jsx", ".ts", ".tsx"},
        "pattern": r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:',
        "description": "Bypasses React's built-in XSS protection, allowing script injection.",
        "recommendation": "Sanitize HTML using DOMPurify before rendering."
    },
    {
        "id": "VULN011",
        "category": "INSECURE_CONFIG",
        "severity": "MEDIUM",
        "title": "Overly Permissive CORS Wildcard",
        "pattern": r'(?i)(?:Access-Control-Allow-Origin\s*[:=]\s*[\'"]\*[\'"]|cors\s*\(\s*\{\s*origin\s*:\s*[\'"]\*[\'"])',
        "description": "Wildcard CORS ('*') allows any external website to make authenticated requests if misconfigured.",
        "recommendation": "Specify explicit allowed domain origins."
    },
    {
        "id": "VULN012",
        "category": "INSECURE_CONFIG",
        "severity": "LOW",
        "title": "Debug Mode Enabled in Configuration",
        "pattern": r'(?i)(?:DEBUG\s*=\s*True|app\.debug\s*=\s*True|\bDEBUG_MODE\b\s*=\s*1)',
        "description": "Running with debug mode enabled can expose interactive debuggers and stack traces.",
        "recommendation": "Ensure DEBUG is False in production environments."
    }
]


def scan_codebase_security(project_path):
    """
    Perform deep static source code analysis (SAST) on an IT project codebase.
    Scans for leaked API keys, tokens, credentials, and code vulnerabilities.
    """
    project_path = os.path.abspath(project_path)
    if not os.path.isdir(project_path):
        return {"error": f"Path is not a valid directory: {project_path}"}

    scan_results = {
        "project_path": project_path,
        "project_name": os.path.basename(project_path),
        "total_files_scanned": 0,
        "total_lines_scanned": 0,
        "languages_detected": {},
        "findings": [],
        "summary": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "TOTAL": 0
        }
    }

    lang_map = {
        ".py": "Python", ".pyw": "Python",
        ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "React JS",
        ".ts": "TypeScript", ".tsx": "React TS",
        ".php": "PHP", ".phtml": "PHP",
        ".java": "Java", ".jsp": "Java JSP",
        ".go": "Go",
        ".rb": "Ruby",
        ".rs": "Rust",
        ".c": "C", ".cpp": "C++", ".h": "C/C++ Header", ".hpp": "C++ Header",
        ".cs": "C#",
        ".kt": "Kotlin",
        ".swift": "Swift",
        ".sh": "Shell Script", ".bash": "Bash", ".zsh": "Zsh", ".ps1": "PowerShell",
        ".sql": "SQL",
        ".env": "Environment Config",
        ".json": "JSON", ".yml": "YAML", ".yaml": "YAML",
        ".xml": "XML", ".toml": "TOML"
    }

    compiled_rules = []
    for rule in CODEBASE_RULES:
        try:
            compiled_rules.append({
                **rule,
                "regex": re.compile(rule["pattern"])
            })
        except Exception:
            pass

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_CODE_DIRS and not d.startswith(".")]

        for filename in files:
            ext = os.path.splitext(filename.lower())[1]
            if ext not in CODE_EXTENSIONS and filename != ".env" and not filename.startswith(".env."):
                continue

            file_full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_full_path, project_path)

            try:
                if os.path.getsize(file_full_path) > 5 * 1024 * 1024:
                    continue
            except Exception:
                continue

            lang = lang_map.get(ext, "Other Code")
            scan_results["languages_detected"][lang] = scan_results["languages_detected"].get(lang, 0) + 1
            scan_results["total_files_scanned"] += 1

            try:
                with open(file_full_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue

            scan_results["total_lines_scanned"] += len(lines)

            for line_idx, line in enumerate(lines, start=1):
                stripped_line = line.strip()
                if not stripped_line or stripped_line.startswith(("#", "//", "/*", "*")):
                    if "PRIVATE KEY" not in stripped_line:
                        continue

                for rule in compiled_rules:
                    # Check target extensions if restricted
                    target_exts = rule.get("target_extensions")
                    if target_exts and ext not in target_exts:
                        continue

                    match = rule["regex"].search(stripped_line)
                    if match:
                        matched_text = match.group(0)
                        snippet = stripped_line
                        if rule["category"] == "LEAKED_SECRET":
                            snippet = snippet.replace(matched_text, mask_secret(matched_text))

                        if len(snippet) > 120:
                            snippet = snippet[:117] + "..."

                        finding = {
                            "id": rule["id"],
                            "file": rel_path,
                            "line": line_idx,
                            "severity": rule["severity"],
                            "category": rule["category"],
                            "title": rule["title"],
                            "description": rule["description"],
                            "snippet": snippet,
                            "recommendation": rule["recommendation"]
                        }

                        scan_results["findings"].append(finding)
                        scan_results["summary"][rule["severity"]] += 1
                        scan_results["summary"]["TOTAL"] += 1

    return scan_results


def print_codebase_report(results, export_markdown=True):
    """Print clean terminal report for IT Project Codebase SAST scan"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'IT PROJECT SOURCE CODE SECURITY AUDIT (SAST)':^70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")

    if results.get("error"):
        print(f"{Colors.RED}[✗] {results['error']}{Colors.RESET}")
        return

    # 1. Project Overview
    print(f"\n{Colors.BOLD}{Colors.WHITE}[1] PROJECT OVERVIEW:{Colors.RESET}")
    print(f"  • Target Project : {Colors.WHITE}{results['project_name']}{Colors.RESET} ({results['project_path']})")
    print(f"  • Files Scanned  : {results['total_files_scanned']:,} files")
    print(f"  • Lines of Code  : {results['total_lines_scanned']:,} lines")
    
    if results["languages_detected"]:
        langs = ", ".join([f"{k} ({v})" for k, v in sorted(results["languages_detected"].items(), key=lambda x: -x[1])[:6]])
        print(f"  • Tech Stacks    : {Colors.CYAN}{langs}{Colors.RESET}")

    # 2. Executive Summary Box
    s = results["summary"]
    print(f"\n{Colors.BOLD}{Colors.WHITE}[2] SECURITY FINDINGS SUMMARY:{Colors.RESET}")
    print(f"  ┌─────────────────────────────────────────────────────────────┐")
    print(f"  │  {Colors.RED}CRITICAL: {s['CRITICAL']:<4}{Colors.RESET}  │  {Colors.MAGENTA}HIGH: {s['HIGH']:<4}{Colors.RESET}  │  {Colors.YELLOW}MEDIUM: {s['MEDIUM']:<4}{Colors.RESET}  │  {Colors.BLUE}LOW: {s['LOW']:<4}{Colors.RESET}  │  {Colors.BOLD}TOTAL: {s['TOTAL']:<4}{Colors.RESET}│")
    print(f"  └─────────────────────────────────────────────────────────────┘")

    # 3. Detailed Findings
    findings = results["findings"]
    if not findings:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ EXCELLENT! No security vulnerabilities or leaked secrets found in the codebase.{Colors.RESET}")
    else:
        print(f"\n{Colors.BOLD}{Colors.WHITE}[3] DETAILED VULNERABILITIES & SECRETS DETECTED:{Colors.RESET}")
        
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(findings, key=lambda x: sev_order.get(x["severity"], 99))

        for idx, f in enumerate(sorted_findings, 1):
            if f["severity"] == "CRITICAL":
                sev_badge = f"{Colors.RED}{Colors.BOLD}[CRITICAL]{Colors.RESET}"
            elif f["severity"] == "HIGH":
                sev_badge = f"{Colors.MAGENTA}{Colors.BOLD}[HIGH]{Colors.RESET}"
            elif f["severity"] == "MEDIUM":
                sev_badge = f"{Colors.YELLOW}{Colors.BOLD}[MEDIUM]{Colors.RESET}"
            else:
                sev_badge = f"{Colors.BLUE}{Colors.BOLD}[LOW]{Colors.RESET}"

            print(f"\n  {idx}. {sev_badge} {Colors.BOLD}{f['title']}{Colors.RESET}")
            print(f"     📁 Location : {Colors.CYAN}{f['file']}:{f['line']}{Colors.RESET}")
            print(f"     💻 Code     : {Colors.WHITE}{f['snippet']}{Colors.RESET}")
            print(f"     ℹ  Details  : {f['description']}")
            print(f"     💡 Fix      : {Colors.GREEN}{f['recommendation']}{Colors.RESET}")

    # 4. Overall Verdict
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'-'*70}{Colors.RESET}")
    print(f"{Colors.BOLD}[*] CODEBASE SECURITY VERDICT:{Colors.RESET}")
    if s["CRITICAL"] > 0:
        print(f"  {Colors.BOLD}{Colors.RED}⛔ CRITICAL RISK: Leaked secrets or API keys detected! Immediate remediation required before pushing to Git.{Colors.RESET}")
    elif s["HIGH"] > 0:
        print(f"  {Colors.BOLD}{Colors.MAGENTA}🚨 HIGH RISK: Potential code execution or injection vulnerabilities found in source code.{Colors.RESET}")
    elif s["MEDIUM"] > 0:
        print(f"  {Colors.BOLD}{Colors.YELLOW}⚠ MEDIUM RISK: Security improvements and hardening recommended.{Colors.RESET}")
    else:
        print(f"  {Colors.BOLD}{Colors.GREEN}✅ CLEAN & SECURE: Codebase follows good security hygiene.{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}\n")

    if export_markdown and findings:
        report_path = os.path.join(results["project_path"], "code_security_audit.md")
        try:
            with open(report_path, "w", encoding="utf-8") as f_out:
                f_out.write(f"# 🛡️ Source Code Security Audit Report\n\n")
                f_out.write(f"**Project:** `{results['project_name']}`  \n")
                f_out.write(f"**Date:** `{time.strftime('%Y-%m-%d %H:%M:%S')}`  \n")
                f_out.write(f"**Files Scanned:** {results['total_files_scanned']} | **Lines of Code:** {results['total_lines_scanned']}\n\n")
                f_out.write(f"## 📊 Summary\n\n")
                f_out.write(f"- 🔴 **CRITICAL:** {s['CRITICAL']}\n")
                f_out.write(f"- 🟠 **HIGH:** {s['HIGH']}\n")
                f_out.write(f"- 🟡 **MEDIUM:** {s['MEDIUM']}\n")
                f_out.write(f"- 🔵 **LOW:** {s['LOW']}\n")
                f_out.write(f"- 📋 **TOTAL FINDINGS:** {s['TOTAL']}\n\n")
                f_out.write(f"## 🔍 Findings List\n\n")
                for idx, f in enumerate(sorted_findings, 1):
                    f_out.write(f"### {idx}. [{f['severity']}] {f['title']}\n")
                    f_out.write(f"- **File:** `{f['file']}:{f['line']}`\n")
                    f_out.write(f"- **Snippet:** `{f['snippet']}`\n")
                    f_out.write(f"- **Description:** {f['description']}\n")
                    f_out.write(f"- **Recommendation:** {f['recommendation']}\n\n")
            print(f"{Colors.GREEN}[✓] Full Security Audit Report exported to: {report_path}{Colors.RESET}")
        except Exception as e:
            pass


def print_report(target_name, file_size, hashes, hidden_info, defender_res, vt_res, disguises=None, image_info=None, ext_info=None):
    """Print formatted security scan summary report"""
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'SECURITY SCAN ANALYSIS REPORT':^70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}")

    # 1. Target Information
    print(f"\n{Colors.BOLD}{Colors.CYAN}[1] TARGET FILE / DIRECTORY INFO:{Colors.RESET}")
    print(f"  • Name: {Colors.WHITE}{target_name}{Colors.RESET}")
    if file_size is not None:
        print(f"  • Size: {file_size / 1024:.2f} KB ({file_size / (1024*1024):.2f} MB)")
    if hashes:
        print(f"  • MD5   : {Colors.WHITE}{hashes['md5']}{Colors.RESET}")
        print(f"  • SHA256: {Colors.WHITE}{hashes['sha256']}{Colors.RESET}")

    # 2. File Extension & Disguise Analysis
    if ext_info:
        print(f"\n{Colors.BOLD}{Colors.CYAN}[2] FILE EXTENSION & SPOOFING ANALYSIS:{Colors.RESET}")
        print(f"  • Full Name on Disk  : {Colors.WHITE}{ext_info['full_name']}{Colors.RESET}")
        
        if ext_info["is_double_ext"]:
            print(f"  • True Real Extension: {Colors.RED}{ext_info['real_ext']} (EXECUTABLE PAYLOAD){Colors.RESET}")
            print(f"  • Fake / Visible Ext : {Colors.YELLOW}{ext_info['fake_ext']}{Colors.RESET} (Deceptive disguise)")
        else:
            print(f"  • True Real Extension: {Colors.GREEN}{ext_info['real_ext']}{Colors.RESET}")

        print(f"  • Detected Binary Header: {Colors.WHITE}{ext_info['magic_type']}{Colors.RESET}")

        if ext_info.get("has_rlo"):
            print(f"  {Colors.RED}🚨 RLO Spoofing Detected: Right-to-Left Override character reverses file extension!{Colors.RESET}")
        if ext_info.get("has_space_padding"):
            print(f"  {Colors.RED}🚨 Space Padding Detected: Long spaces used to push executable extension off-screen!{Colors.RESET}")
        if ext_info.get("magic_mismatch"):
            print(f"  {Colors.RED}🚨 Mismatch Detected: True format is '{ext_info['magic_type']}' but extension claims '{ext_info['real_ext']}'!{Colors.RESET}")

    # 3. Hidden items & Disguise Detection
    sec_num = 3 if ext_info else 2
    print(f"\n{Colors.BOLD}{Colors.CYAN}[{sec_num}] HIDDEN FILES & DIRECTORIES CHECK:{Colors.RESET}")
    
    has_hidden = False
    if hidden_info:
        hidden_files = hidden_info.get("hidden_files", [])
        hidden_dirs = hidden_info.get("hidden_dirs", [])
        suspicious_files = hidden_info.get("suspicious_files", [])

        if hidden_dirs:
            has_hidden = True
            print(f"  {Colors.YELLOW}⚠ Detected {len(hidden_dirs)} Hidden Directory/Directories:{Colors.RESET}")
            for d in hidden_dirs[:10]:
                print(f"    - [HIDDEN DIR] {d}")
            if len(hidden_dirs) > 10:
                print(f"    ... and {len(hidden_dirs) - 10} more hidden directories")

        if hidden_files:
            has_hidden = True
            print(f"  {Colors.YELLOW}⚠ Detected {len(hidden_files)} Hidden File(s):{Colors.RESET}")
            for f in hidden_files[:10]:
                print(f"    - [HIDDEN FILE] {f}")
            if len(hidden_files) > 10:
                print(f"    ... and {len(hidden_files) - 10} more hidden files")

        if suspicious_files:
            has_hidden = True
            print(f"  {Colors.RED}🚨 Detected {len(suspicious_files)} Dangerous / Executable File(s) inside:{Colors.RESET}")
            for s in suspicious_files[:10]:
                print(f"    - {s}")
            if len(suspicious_files) > 10:
                print(f"    ... and {len(suspicious_files) - 10} more suspicious files")

    if disguises:
        has_hidden = True
        print(f"  {Colors.RED}🚨 FILE DISGUISE WARNING:{Colors.RESET}")
        for d in disguises:
            print(f"    - {d}")

    if not has_hidden and not (ext_info and (ext_info.get("is_double_ext") or ext_info.get("has_rlo") or ext_info.get("magic_mismatch"))):
        print(f"  {Colors.GREEN}✓ No hidden files, hidden directories, or suspicious disguises found.{Colors.RESET}")

    # 4. Image Security Inspection (if applicable)
    has_image_threat = False
    has_image_warning = False
    if image_info and image_info.get("is_image"):
        sec_num += 1
        print(f"\n{Colors.BOLD}{Colors.CYAN}[{sec_num}] IMAGE SECURITY & STEGANOGRAPHY CHECK:{Colors.RESET}")
        print(f"  • Format: {Colors.WHITE}{image_info.get('format_detected')}{Colors.RESET}")
        
        threats = image_info.get("threats", [])
        warnings = image_info.get("warnings", [])

        if threats:
            has_image_threat = True
            print(f"  {Colors.RED}🚨 Critical Image Threats Detected:{Colors.RESET}")
            for t in threats:
                print(f"    - {t}")

        if warnings:
            has_image_warning = True
            print(f"  {Colors.YELLOW}⚠ Image Security Warnings:{Colors.RESET}")
            for w in warnings:
                print(f"    - {w}")

        if not threats and not warnings:
            print(f"  {Colors.GREEN}✓ Clean image structure. No appended payloads or embedded scripts found.{Colors.RESET}")

    # 5. Windows Defender Result
    sec_num += 1
    print(f"\n{Colors.BOLD}{Colors.CYAN}[{sec_num}] OFFLINE SCAN (WINDOWS DEFENDER):{Colors.RESET}")
    if defender_res.get("supported"):
        if defender_res.get("clean") is True:
            print(f"  {Colors.GREEN}✓ {defender_res['message']}{Colors.RESET}")
        elif defender_res.get("clean") is False:
            print(f"  {Colors.RED}❌ {defender_res['message']}{Colors.RESET}")
            if "details" in defender_res:
                print(f"     Details: {defender_res['details'].strip()}")
        else:
            print(f"  {Colors.YELLOW}ℹ {defender_res['message']}{Colors.RESET}")
    else:
        print(f"  {Colors.YELLOW}ℹ {defender_res.get('message', 'Unavailable')}{Colors.RESET}")

    # 6. VirusTotal Result
    sec_num += 1
    print(f"\n{Colors.BOLD}{Colors.CYAN}[{sec_num}] ONLINE LOOKUP (VIRUSTOTAL):{Colors.RESET}")
    if vt_res.get("has_api") and vt_res.get("found"):
        mal = vt_res.get("malicious", 0)
        susp = vt_res.get("suspicious", 0)
        total = vt_res.get("total", 0)

        if mal > 0:
            print(f"  {Colors.RED}❌ MALWARE DETECTED: {mal}/{total} security engines flagged this file as malicious!{Colors.RESET}")
            if vt_res.get("detections"):
                print(f"  {Colors.YELLOW}Key Detections:{Colors.RESET}")
                for det in vt_res["detections"]:
                    print(f"    • {det}")
        elif susp > 0:
            print(f"  {Colors.YELLOW}⚠ SUSPICIOUS: {susp}/{total} engines flagged this file as suspicious.{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}✓ Clean: 0/{total} engines detected threats.{Colors.RESET}")
    elif vt_res.get("error"):
        print(f"  {Colors.YELLOW}⚠ {vt_res['error']}{Colors.RESET}")
    else:
        print(f"  {Colors.WHITE}ℹ {vt_res.get('message', '')}{Colors.RESET}")

    if vt_res.get("vt_url"):
        print(f"  🔗 Direct VirusTotal Report: {Colors.BLUE}{vt_res['vt_url']}{Colors.RESET}")

    # OVERALL VERDICT
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'-'*70}{Colors.RESET}")
    print(f"{Colors.BOLD}[*] OVERALL ASSESSMENT:{Colors.RESET}")
    
    is_malicious = (
        (defender_res.get("clean") is False) or
        (vt_res.get("has_api") and vt_res.get("malicious", 0) > 0) or
        has_image_threat or
        (ext_info and (ext_info.get("has_rlo") or ext_info.get("magic_mismatch")))
    )
    is_warning = (
        has_hidden or 
        (vt_res.get("has_api") and vt_res.get("suspicious", 0) > 0) or
        has_image_warning or
        (ext_info and ext_info.get("is_double_ext"))
    )

    if is_malicious:
        print(f"  {Colors.BOLD}{Colors.RED}⛔ DANGER: The file contains VIRUS / MALWARE / DANGEROUS PAYLOAD! Do NOT open or execute this file.{Colors.RESET}")
    elif is_warning:
        print(f"  {Colors.BOLD}{Colors.YELLOW}⚠ WARNING: Hidden items, double extensions or steganography detected. Inspect carefully before opening.{Colors.RESET}")
    else:
        print(f"  {Colors.BOLD}{Colors.GREEN}✅ SAFE: No security threats or hidden items detected.{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.RESET}\n")


def scan_target(target, api_key=None):
    """Coordinate scanning workflow for URLs, Files, Folders, and Archives"""
    target = target.strip().strip('"').strip("'")
    if not target:
        print(f"{Colors.RED}[!] Input path or URL cannot be empty.{Colors.RESET}")
        return

    temp_dir = None
    file_path = None
    is_url = target.startswith("http://") or target.startswith("https://")

    try:
        if is_url:
            temp_dir = tempfile.mkdtemp(prefix="vt_scan_")
            downloaded = download_file(target, temp_dir)
            if not downloaded:
                return
            file_path = downloaded
        else:
            if not os.path.exists(target):
                print(f"{Colors.RED}[✗] Path does not exist: {target}{Colors.RESET}")
                return
            file_path = os.path.abspath(target)

        # Target is a DIRECTORY
        if os.path.isdir(file_path):
            print(f"{Colors.BLUE}[*] Scanning directory: {file_path}{Colors.RESET}")
            hidden_info = scan_directory_hidden(file_path)
            defender_res = scan_with_windows_defender(file_path)
            print_report(
                target_name=os.path.basename(file_path) + " (Directory)",
                file_size=None,
                hashes=None,
                hidden_info=hidden_info,
                defender_res=defender_res,
                vt_res={"message": "Cannot query entire directories on VirusTotal. Archive the folder to calculate a hash."},
                disguises=None,
                image_info=None,
                ext_info=None
            )

            # Also perform Codebase SAST Security Audit if source files exist
            print(f"{Colors.BLUE}[*] Checking for source code files to perform SAST security audit...{Colors.RESET}")
            code_results = scan_codebase_security(file_path)
            if code_results.get("total_files_scanned", 0) > 0:
                print_codebase_report(code_results)

            return

        # Target is a FILE
        file_size = os.path.getsize(file_path)
        print(f"{Colors.BLUE}[*] Computing file hashes (MD5, SHA256)...{Colors.RESET}")
        hashes = calculate_hashes(file_path)

        # File Extension & Disguise analysis
        ext_info = analyze_file_extension(file_path)
        disguises = check_disguised_file(file_path)

        # Deep Image Security Scan (if image format or extension)
        image_info = scan_image_security(file_path)
        if image_info:
            print(f"{Colors.BLUE}[*] Image detected ({image_info.get('format_detected')}). Running steganography & payload checks...{Colors.RESET}")

        # Check archive internals (ZIP/TAR)
        hidden_info = None
        if zipfile.is_zipfile(file_path) or tarfile.is_tarfile(file_path):
            print(f"{Colors.BLUE}[*] Archive detected. Inspecting internal structure...{Colors.RESET}")
            hidden_info = scan_archive_contents(file_path)

        # Windows Defender offline scan
        print(f"{Colors.BLUE}[*] Scanning with Windows Defender...{Colors.RESET}")
        defender_res = scan_with_windows_defender(file_path)

        # VirusTotal lookup
        print(f"{Colors.BLUE}[*] Querying VirusTotal...{Colors.RESET}")
        vt_res = check_virustotal(hashes["sha256"], api_key=api_key)

        # Output the report
        print_report(
            target_name=os.path.basename(file_path),
            file_size=file_size,
            hashes=hashes,
            hidden_info=hidden_info,
            defender_res=defender_res,
            vt_res=vt_res,
            disguises=disguises,
            image_info=image_info,
            ext_info=ext_info
        )

    finally:
        # Clean up temporary downloaded file
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass


def manage_windows_extension_settings():
    """View and toggle Windows Explorer settings for displaying file extensions and hidden files"""
    if sys.platform != "win32":
        print(f"{Colors.YELLOW}[!] This setting is only available on Windows.{Colors.RESET}")
        return

    import winreg
    reg_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
        hide_ext, _ = winreg.QueryValueEx(key, "HideFileExt")
        hidden, _ = winreg.QueryValueEx(key, "Hidden")
        show_super_hidden, _ = winreg.QueryValueEx(key, "ShowSuperHidden")
        winreg.CloseKey(key)
    except Exception:
        hide_ext, hidden, show_super_hidden = 1, 2, 0

    print(f"\n{Colors.BOLD}{Colors.CYAN}--- WINDOWS FILE EXTENSION & HIDDEN FILES SETTINGS ---{Colors.RESET}")
    print(f"  • File Extensions Visibility : {Colors.RED + 'HIDDEN (DANGEROUS)' if hide_ext == 1 else Colors.GREEN + 'ALWAYS VISIBLE (SAFE)'}{Colors.RESET}")
    print(f"  • Hidden Files & Folders     : {Colors.GREEN + 'VISIBLE' if hidden == 1 else Colors.YELLOW + 'HIDDEN'}{Colors.RESET}")
    print(f"  • Protected System Files     : {Colors.GREEN + 'VISIBLE' if show_super_hidden == 1 else Colors.YELLOW + 'HIDDEN'}{Colors.RESET}")
    print("\nRecommendations:")
    print("  Showing file extensions helps you see fake extensions (e.g. photo.jpg.exe) directly in File Explorer.")
    print("  [1] Enable ALWAYS SHOW file extensions & show hidden files (Recommended)")
    print("  [2] Revert to Windows default (Hide file extensions)")
    print("  [0] Back to Main Menu")

    choice = input(f"\n{Colors.CYAN}Select option (1/2/0): {Colors.RESET}").strip()
    if choice == "1":
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "HideFileExt", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(key, "Hidden", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ShowSuperHidden", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)

            # Refresh Windows Explorer live
            import ctypes
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, 0, 0)
            print(f"{Colors.GREEN}[✓] Successfully enabled! File extensions and hidden files are now ALWAYS visible in File Explorer.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[✗] Failed to update Windows registry: {e}{Colors.RESET}")

    elif choice == "2":
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "HideFileExt", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "Hidden", 0, winreg.REG_DWORD, 2)
            winreg.SetValueEx(key, "ShowSuperHidden", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)

            import ctypes
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, 0, 0)
            print(f"{Colors.YELLOW}[✓] Reverted to Windows default settings.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[✗] Failed to update Windows registry: {e}{Colors.RESET}")


def manage_api_key(config):
    """Manage VirusTotal API Key settings"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}--- VIRUSTOTAL API KEY CONFIGURATION ---{Colors.RESET}")
    current_key = config.get("virustotal_api_key", "")
    if current_key:
        masked = current_key[:6] + "..." + current_key[-4:]
        print(f"Current API Key: {Colors.GREEN}{masked}{Colors.RESET}")
    else:
        print(f"Current API Key: {Colors.YELLOW}(Not configured){Colors.RESET}")
    
    print("You can get a free API key by creating an account at https://www.virustotal.com")
    new_key = input("Enter new API Key (or press Enter to keep current, type 'clear' to remove): ").strip()
    
    if new_key.lower() == "clear":
        config.pop("virustotal_api_key", None)
        save_config(config)
        print(f"{Colors.GREEN}[✓] API Key removed successfully.{Colors.RESET}")
    elif new_key:
        config["virustotal_api_key"] = new_key
        save_config(config)
        print(f"{Colors.GREEN}[✓] API Key saved successfully.{Colors.RESET}")


def main():
    print_banner()
    config = load_config()

    # Support CLI arguments: python main.py <target>
    if len(sys.argv) > 1:
        target = sys.argv[1]
        api_key = config.get("virustotal_api_key")
        scan_target(target, api_key=api_key)
        return

    while True:
        api_key = config.get("virustotal_api_key")
        vt_status = f"{Colors.GREEN}[Configured]{Colors.RESET}" if api_key else f"{Colors.YELLOW}[Not set - direct link provided]{Colors.RESET}"
        
        print(f"{Colors.BOLD}Options:{Colors.RESET}")
        print(f"  [1] Paste Download Link (URL) or File/Directory Path to scan")
        print(f"  [2] Scan IT Project Codebase (Vulnerabilities, Leaked Secrets, SAST Audit)")
        print(f"  [3] Configure VirusTotal API Key {vt_status}")
        print(f"  [4] Windows Settings: Always Show File Extensions & Hidden Files")
        print(f"  [0] Exit")
        
        choice = input(f"\n{Colors.CYAN}Select an option (1/2/3/4/0): {Colors.RESET}").strip()

        if choice == "1":
            target = input(f"\n{Colors.BOLD}Enter URL or File/Directory Path:{Colors.RESET} ").strip()
            if target:
                scan_target(target, api_key=api_key)
        elif choice == "2":
            code_path = input(f"\n{Colors.BOLD}Enter IT Project Folder Path (or press Enter for current directory):{Colors.RESET} ").strip()
            if not code_path:
                code_path = os.getcwd()
            code_results = scan_codebase_security(code_path)
            print_codebase_report(code_results)
        elif choice == "3":
            manage_api_key(config)
        elif choice == "4":
            manage_windows_extension_settings()
        elif choice == "0":
            print(f"\n{Colors.GREEN}Thank you for using the scanner! Goodbye.{Colors.RESET}")
            break
        else:
            print(f"{Colors.RED}[!] Invalid option, please try again.{Colors.RESET}")
        
        print("\n" + "-"*50 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Execution interrupted by user.{Colors.RESET}")
        sys.exit(0)

