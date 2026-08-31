# 🛡️ Virus & Hidden Files / Folders Scanner

A powerful, lightweight Python security tool designed to scan download URLs, local files, directories, compressed archives, and images for malware, virus threats, hidden files/directories, and steganography payloads.

🔗 **Repository:** [https://github.com/hongquang699/check-file](https://github.com/hongquang699/check-file)

---

## 🌟 Key Features

### 1. 🌐 Flexible Input Handling
- **Direct Download URLs:** Paste `http://` or `https://` links; the tool downloads the target securely to a temporary sandbox, inspects it, and safely cleans up afterwards.
- **Local Files & Folders:** Scan any local file or entire folder tree on your system.
- **Compressed Archives:** Deeply inspects `.zip`, `.tar`, `.gz`, and `.rar` archives without extracting risky contents to disk.

### 2. 👁️ Hidden Files & Directories Inspection
- Detects hidden files and folders starting with a leading dot (`.`).
- Checks Windows file attributes (`FILE_ATTRIBUTE_HIDDEN` and `FILE_ATTRIBUTE_SYSTEM`).
- Identifies suspicious hidden structures nestled inside archive files.

### 3. 🎭 Disguise & Double Extension Detection
- Detects dangerous double extensions (e.g., `document.pdf.exe`, `photo.jpg.scr`, `invoice.docx.vbs`).
- Inspects **Magic Bytes** to catch Windows PE (`EXE/DLL`) or Linux `ELF` binaries masquerading as harmless image or document extensions.

### 4. 🖼️ Deep Image Security & Steganography Analysis
- **Supported Formats:** JPG/JPEG, PNG, GIF, BMP, WEBP, SVG, TIFF, PSD.
- **Steganography & Trailing Payloads:** Checks for unauthorized data appended past standard End-of-Image markers (`EOI / IEND / trailer`).
- **Polyglot Detection:** Detects embedded executables (`MZ/PE`, `ELF`) or archives (`RarJPEG`, Zip-in-PNG) hidden within images.
- **SVG Vector Security:** Scans for Cross-Site Scripting (XSS), malicious JavaScript (`<script>`, `onload=`, `onerror=`, `javascript:`), and XML External Entity (`XXE`) exploits.
- **WebShell Detection:** Identifies embedded PHP, eval, PowerShell, or command strings inside image metadata.

### 5. 🔍 Dual-Layer Antivirus Scanning
- **Offline (Free & Native):** Directly integrates with the built-in **Windows Defender** engine (`MpCmdRun.exe`).
- **Online (VirusTotal):** Computes `MD5` and `SHA256` hashes to query the VirusTotal v3 API or generate direct report URLs.

### 6. 🚀 Automated GitHub Synchronization
- Push updates directly to GitHub via `github_service.py` or 1-click batch scripts.
- Supports scheduled background pushes and secure token authentication via `.env`.

---

## 📁 Project Structure

```
check-file/
├── main.py              # Main security scanning engine & CLI interface
├── github_service.py    # GitHub automated/manual sync service
├── run_scanner.bat      # 1-Click Windows shortcut to scan files/URLs
├── push_github.bat      # 1-Click Windows shortcut to push code to GitHub
├── robots.txt           # Web crawler directives
├── .env.example         # Template for environment variables (GITHUB_TOKEN)
├── .gitignore           # Git ignore rules for sensitive config and temporary files
└── README.md            # Project documentation
```

---

## 🚀 Quick Start Guide

### Option 1: Windows 1-Click Batch Scripts (.bat)
- **To Scan:** Double-click **`run_scanner.bat`** ➔ Paste your download URL or file path ➔ Press `Enter`.
- **To Push Code:** Double-click **`push_github.bat`** ➔ Enter a commit message (or press `Enter` for auto-timestamp).

---

### Option 2: Command Line Interface (CLI)

#### 1. Interactive Menu
```bash
python main.py
```
- Select `1` to paste a URL or file/directory path.
- Select `2` to configure your VirusTotal API key *(optional)*.
- Select `0` to exit.

#### 2. Direct CLI Scanning
```bash
# Scan a remote download URL:
python main.py "https://example.com/sample_file.zip"

# Scan a local file (e.g. image, archive, document):
python main.py "C:\Users\Downloads\sample_image.jpg"

# Scan an entire directory:
python main.py "C:\Users\Downloads\TargetFolder"
```

#### 3. GitHub Service Operations
```bash
# Manual Push with custom commit message:
python github_service.py "Update scanner with image security features"
```

---

## ⚙️ Configuration (Optional)

### VirusTotal API Key
You can add your free API key from [virustotal.com](https://www.virustotal.com) through menu option `2` in `main.py`. The key will be securely saved in `config.json` (which is excluded by `.gitignore`).

### GitHub Personal Access Token
To enable non-interactive GitHub pushes:
1. Copy `.env.example` to `.env`:
   ```bash
   copy .env.example .env
   ```
2. Open `.env` and insert your token:
   ```env
   GITHUB_TOKEN=ghp_your_personal_access_token_here
   ```

---

## 🔒 Security & Privacy Notice
- Downloaded files from URLs are scanned in a temporary isolated sandbox directory and **automatically deleted** immediately after the scan completes.
- No files are uploaded to third-party servers unless you specifically configure and invoke API upload functions; VirusTotal queries use only the file's cryptographic hash (`SHA256`).

---

## 📄 License
This project is open-source and available under the MIT License.
