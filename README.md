# Virus & Hidden Files / Folders Scanner (Python)

A Python security tool that allows you to paste a download URL or a local file/folder path to detect malware, hidden directories/files, disguised executables, and virus threats.

---

## 🌟 Key Features

1. **URL Download & Local Path Support**:
   - Paste direct download links (`http://...`, `https://...`); the tool safely downloads the target to a temporary directory and scans it.
   - Or provide local file paths, directories, or compressed archives (`.zip`, `.tar`, `.rar`...).
2. **Hidden Files & Directories Inspection**:
   - Detects files/folders with a leading dot `.` or Windows `Hidden`/`System` attributes.
   - Deeply inspects the contents of archive files (`ZIP`, `TAR`) without extracting them to disk.
3. **Malware Disguise & Double Extension Detection**:
   - Identifies dangerous double extensions like `document.pdf.exe`, `photo.jpg.vbs`, etc.
   - Validates actual file formats using **Magic Bytes** to catch Windows executables (`EXE/PE`, `ELF`) disguised as documents or images.
4. **Dual-Layer Antivirus Scanning (Offline & Online)**:
   - **Offline (Free & Built-in)**: Uses the native **Windows Defender** engine (`MpCmdRun.exe`).
   - **Online (VirusTotal)**: Calculates `SHA256` hashes to query VirusTotal (supports API Key for automatic reports or generates direct lookup URLs).

---

## 🚀 How to Use

### Method 1: Interactive Menu
Open Terminal or PowerShell in the project directory and run:
```bash
python main.py
```
Then select:
- `1`: Paste a download URL or a local file/folder path to scan.
- `2`: Configure/Save your VirusTotal API Key *(Optional - get one for free at [virustotal.com](https://www.virustotal.com))*.
- `0`: Exit.

### Method 2: Quick CLI Scanning
```bash
# Scan a file via direct download URL:
python main.py "https://example.com/target_file.zip"

# Scan a local file:
python main.py "C:\Users\Downloads\target_file.zip"

# Scan an entire directory:
python main.py "C:\Users\Downloads\TargetFolder"
```
