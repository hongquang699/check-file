#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Service - Automated & Manual Code Synchronization
Features:
  - Manual Git Push via CLI or script execution
  - Automated Scheduled Pushes (HH:MM daily time slots)
  - Automatic detection of GITHUB_TOKEN from system environment or .env file
  - Target Repository: https://github.com/hongquang699/check-file
"""
import os
import sys
import subprocess

# Configure UTF-8 encoding for Windows Terminal
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import threading
import time
from datetime import datetime

# Project root directory
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(PROJECT_ROOT, "data", "system_config.json")
DEFAULT_REPO_URL = "https://github.com/hongquang699/check-file.git"

_lock = threading.Lock()


def _load_config():
    """Load configuration from system_config.json"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_config(cfg: dict):
    """Save configuration to system_config.json"""
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        existing = _load_config()
        existing.update(cfg)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[GitHubService] Config write error: {e}")


def _load_github_token():
    """Read GitHub Token securely from environment variables or .env file"""
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token
        
    env_paths = [
        os.path.join(PROJECT_ROOT, ".env"),
        os.path.join(os.path.dirname(PROJECT_ROOT), ".env")
    ]
    for path in env_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("GITHUB_TOKEN="):
                            return line.split("GITHUB_TOKEN=", 1)[1].strip().strip('"').strip("'")
            except Exception:
                pass
    return None


def git_push(commit_message: str = None) -> dict:
    """
    Execute git add, commit, and push to remote repository.
    Returns dict: { success: bool, message: str, output: str }
    """
    if not commit_message:
        commit_message = f"Auto update - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    cfg = _load_config()
    repo_url_base = cfg.get("github_repo_url", DEFAULT_REPO_URL)
    clean_repo = repo_url_base.replace("https://", "").replace("http://", "")
    if clean_repo.endswith("/"):
        clean_repo = clean_repo[:-1]
    if not clean_repo.endswith(".git"):
        clean_repo += ".git"

    try:
        logs = []

        # Determine current active branch (e.g. main or master)
        branch_result = subprocess.run(
            ["git", "-c", "safe.directory=*", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True, text=True, encoding="utf-8", timeout=10
        )
        current_branch = branch_result.stdout.strip() or "main"
        if current_branch == "HEAD":
            current_branch = "main"

        # git add .
        result = subprocess.run(
            ["git", "-c", "safe.directory=*", "add", "."],
            cwd=PROJECT_ROOT,
            capture_output=True, text=True, encoding="utf-8", timeout=30
        )
        logs.append(f"[git add] {result.stdout.strip() or result.stderr.strip() or 'OK'}")
        if result.returncode != 0:
            return {"success": False, "message": "git add failed", "output": "\n".join(logs)}

        # git commit
        result = subprocess.run(
            ["git", "-c", "safe.directory=*", "-c", "user.name=Check-File Backup", "-c", "user.email=backup@check-file.local", "commit", "-m", commit_message],
            cwd=PROJECT_ROOT,
            capture_output=True, text=True, encoding="utf-8", timeout=30
        )
        commit_out = result.stdout.strip() or result.stderr.strip()
        logs.append(f"[git commit] {commit_out}")

        # If nothing to commit, return success
        if result.returncode != 0 and "nothing to commit" in commit_out.lower():
            _save_config({"last_github_push_time": datetime.now().isoformat(), "change_counter": 0})
            return {"success": True, "message": "Nothing to commit, repository is up to date", "output": "\n".join(logs)}

        if result.returncode != 0:
            return {"success": False, "message": "git commit failed", "output": "\n".join(logs)}

        # git push
        token = _load_github_token()
        success_push = False
        push_out = ""
        
        if token:
            # Embed token into URL for headless/automated authentication
            auth_repo_url = f"https://{token}@{clean_repo}"
            push_args = ["git", "-c", "safe.directory=*", "push", auth_repo_url, current_branch]
            result = subprocess.run(
                push_args,
                cwd=PROJECT_ROOT,
                capture_output=True, text=True, encoding="utf-8", timeout=60
            )
            push_out = result.stdout.strip() or result.stderr.strip()
            logs.append(f"[git push with token] {push_out}")
            if result.returncode == 0:
                success_push = True
                
        if not success_push:
            # Fallback to default push using Git Credential Manager or SSH
            push_args = ["git", "-c", "safe.directory=*", "push", "origin", current_branch]
            result = subprocess.run(
                push_args,
                cwd=PROJECT_ROOT,
                capture_output=True, text=True, encoding="utf-8", timeout=60
            )
            push_out = result.stdout.strip() or result.stderr.strip()
            logs.append(f"[git push origin] {push_out}")
            if result.returncode == 0:
                success_push = True

        if success_push:
            _save_config({
                "last_github_push_time": datetime.now().isoformat(),
                "change_counter": 0
            })
            return {"success": True, "message": "Code pushed to GitHub successfully!", "output": "\n".join(logs)}
        else:
            return {"success": False, "message": "git push failed. Check GITHUB_TOKEN, remote URL or repository permissions.", "output": "\n".join(logs)}

    except subprocess.TimeoutExpired:
        return {"success": False, "message": "Git command execution timed out", "output": ""}
    except FileNotFoundError:
        return {"success": False, "message": "Git command not found. Please install Git and add it to PATH.", "output": ""}
    except Exception as e:
        return {"success": False, "message": f"Unexpected error: {str(e)}", "output": ""}


def increment_change_counter():
    """
    Increment change_counter when modifications occur.
    Triggers auto-push if counter exceeds threshold.
    """
    with _lock:
        cfg = _load_config()
        if not cfg.get("github_auto_push", False):
            return

        trigger_count = int(cfg.get("github_push_trigger_count", 0))
        if trigger_count <= 0:
            return

        counter = int(cfg.get("change_counter", 0)) + 1
        _save_config({"change_counter": counter})

        if counter >= trigger_count:
            # Trigger background push
            threading.Thread(
                target=git_push,
                args=(f"Auto backup (trigger: {counter} changes)",),
                daemon=True
            ).start()


def start_auto_push_scheduler():
    """
    Start scheduled auto-push thread based on daily time slots (HH:MM).
    Checks once every minute.
    """
    def _schedule_loop():
        while True:
            cfg = _load_config()
            if not cfg.get("github_auto_push", False):
                time.sleep(60)
                continue

            now = datetime.now()
            today_str = now.strftime('%Y-%m-%d')
            current_time_str = now.strftime('%H:%M')

            # Check up to 3 time slots
            for i in range(1, 4):
                backup_time = cfg.get(f"backup_time_{i}", "")
                if backup_time and backup_time.strip() == current_time_str:
                    last_backup_date = cfg.get(f"last_backup_date_{i}", "")
                    if last_backup_date != today_str:
                        git_push(f"Scheduled auto backup (Slot {i}: {backup_time})")
                        _save_config({f"last_backup_date_{i}": today_str})

            time.sleep(60)

    t = threading.Thread(target=_schedule_loop, daemon=True)
    t.start()


def get_github_config() -> dict:
    """Retrieve GitHub auto-push settings"""
    cfg = _load_config()
    return {
        "github_auto_push": cfg.get("github_auto_push", False),
        "backup_time_1": cfg.get("backup_time_1", "02:00"),
        "backup_time_2": cfg.get("backup_time_2", "14:00"),
        "backup_time_3": cfg.get("backup_time_3", "20:00"),
        "github_repo_url": cfg.get("github_repo_url", DEFAULT_REPO_URL),
        "last_github_push_time": cfg.get("last_github_push_time", "")
    }


def save_github_config(auto_push: bool, backup_time_1: str, backup_time_2: str, backup_time_3: str, repo_url: str = ""):
    """Save GitHub auto-push settings"""
    _save_config({
        "github_auto_push": auto_push,
        "backup_time_1": backup_time_1 or "02:00",
        "backup_time_2": backup_time_2 or "14:00",
        "backup_time_3": backup_time_3 or "20:00",
        "github_repo_url": repo_url or DEFAULT_REPO_URL
    })


if __name__ == "__main__":
    import sys
    print("=== GitHub Service ===")
    print(f"Target Repo: {DEFAULT_REPO_URL}")
    print("Executing git push...")
    msg = sys.argv[1] if len(sys.argv) > 1 else None
    res = git_push(msg)
    print(f"Result: {res['message']}")
    if res.get("output"):
        print(f"Details:\n{res['output']}")
