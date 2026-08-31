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

# Magic bytes to identify executable headers
PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"
ZIP_MAGIC = b"PK\x03\x04"
RAR_MAGIC = b"Rar!\x1a\x07"
PDF_MAGIC = b"%PDF"


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


def check_disguised_file(file_path):
    """Check if file has double extensions or disguised executable headers"""
    suspicious_reports = []
    name = os.path.basename(file_path)
    lower_name = name.lower()

    # 1. Double extension check (e.g., sample.pdf.exe)
    parts = name.split(".")
    if len(parts) > 2:
        ext_last = f".{parts[-1].lower()}"
        ext_prev = f".{parts[-2].lower()}"
        if ext_last in DANGEROUS_EXTENSIONS:
            suspicious_reports.append(
                f"Dangerous double extension detected ({ext_prev}{ext_last}) - potential document disguise!"
            )

    # 2. Magic Bytes validation
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)

        is_pe = header.startswith(PE_MAGIC)
        is_elf = header.startswith(ELF_MAGIC)
        
        non_exec_extensions = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".docx", ".xlsx", ".pptx", ".mp3", ".mp4"}
        ext = os.path.splitext(lower_name)[1]
        
        if is_pe and ext in non_exec_extensions:
            suspicious_reports.append(
                f"Windows Executable (PE/EXE) disguised as extension '{ext}'!"
            )
        elif is_elf and ext in non_exec_extensions:
            suspicious_reports.append(
                f"Linux Executable (ELF) disguised as extension '{ext}'!"
            )
    except Exception:
        pass

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


def print_report(target_name, file_size, hashes, hidden_info, defender_res, vt_res, disguises=None):
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

    # 2. Hidden items & Disguise Detection
    print(f"\n{Colors.BOLD}{Colors.CYAN}[2] HIDDEN FILES & DIRECTORIES CHECK:{Colors.RESET}")
    
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

    if not has_hidden:
        print(f"  {Colors.GREEN}✓ No hidden files, hidden directories, or suspicious disguises found.{Colors.RESET}")

    # 3. Windows Defender Result
    print(f"\n{Colors.BOLD}{Colors.CYAN}[3] OFFLINE SCAN (WINDOWS DEFENDER):{Colors.RESET}")
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

    # 4. VirusTotal Result
    print(f"\n{Colors.BOLD}{Colors.CYAN}[4] ONLINE LOOKUP (VIRUSTOTAL):{Colors.RESET}")
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

    # 5. OVERALL VERDICT
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'-'*70}{Colors.RESET}")
    print(f"{Colors.BOLD}[*] OVERALL ASSESSMENT:{Colors.RESET}")
    
    is_malicious = (
        (defender_res.get("clean") is False) or
        (vt_res.get("has_api") and vt_res.get("malicious", 0) > 0)
    )
    is_warning = (
        has_hidden or 
        (vt_res.get("has_api") and vt_res.get("suspicious", 0) > 0)
    )

    if is_malicious:
        print(f"  {Colors.BOLD}{Colors.RED}⛔ DANGER: The file contains VIRUS / MALWARE! Do NOT open or execute this file.{Colors.RESET}")
    elif is_warning:
        print(f"  {Colors.BOLD}{Colors.YELLOW}⚠ WARNING: Hidden files/folders or suspicious extensions detected. Inspect carefully before opening.{Colors.RESET}")
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
                disguises=None
            )
            return

        # Target is a FILE
        file_size = os.path.getsize(file_path)
        print(f"{Colors.BLUE}[*] Computing file hashes (MD5, SHA256)...{Colors.RESET}")
        hashes = calculate_hashes(file_path)

        # Check for disguise / double extensions
        disguises = check_disguised_file(file_path)

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
            disguises=disguises
        )

    finally:
        # Clean up temporary downloaded file
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass


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
        print(f"  [0] Exit")
        
        choice = input(f"\n{Colors.CYAN}Select an option (1/2/0): {Colors.RESET}").strip()

        if choice == "1":
            target = input(f"\n{Colors.BOLD}Enter URL or File/Directory Path:{Colors.RESET} ").strip()
            if target:
                scan_target(target, api_key=api_key)
        elif choice == "2":
            manage_api_key(config)
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
