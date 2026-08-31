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
        print(f"  [2] Configure VirusTotal API Key {vt_status}")
        print(f"  [3] Windows Settings: Always Show File Extensions & Hidden Files")
        print(f"  [0] Exit")
        
        choice = input(f"\n{Colors.CYAN}Select an option (1/2/3/0): {Colors.RESET}").strip()

        if choice == "1":
            target = input(f"\n{Colors.BOLD}Enter URL or File/Directory Path:{Colors.RESET} ").strip()
            if target:
                scan_target(target, api_key=api_key)
        elif choice == "2":
            manage_api_key(config)
        elif choice == "3":
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

