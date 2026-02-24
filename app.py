#!/usr/bin/env python3
"""
LOCAL-ONLY gocryptfs WebUI

Setup:
  pip install fastapi uvicorn
Run:
  python3 app.py
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Literal, Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field


app = FastAPI()


class InitRequest(BaseModel):
    enc_path: str = Field(..., description="Absolute path to encrypted folder")
    password: str
    password_confirm: str


class MountRequest(BaseModel):
    enc_path: str = Field(..., description="Absolute path to encrypted folder")
    mount_path: str = Field(..., description="Absolute path to mount point")
    auth_mode: Literal["password", "masterkey"] = "password"
    password: str = ""
    master_key: str = ""
    read_only: bool = False
    allow_other: bool = False
    sharedstorage: bool = False
    reverse: bool = False
    aessiv: bool = False
    plaintextnames: bool = False
    xchacha: bool = False
    idle_timeout: str = ""
    kernel_options: str = ""


class UnmountRequest(BaseModel):
    mount_path: str = Field(..., description="Absolute path to mount point")


class InfoRequest(BaseModel):
    enc_path: str = Field(..., description="Absolute path to encrypted folder")


def _is_abs_path(path: str) -> bool:
    path = path.strip()
    return bool(path) and os.path.isabs(path) and "\x00" not in path


def _path_exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except OSError:
        return False


def _is_dir_empty(path: str) -> bool:
    try:
        return os.path.isdir(path) and not os.listdir(path)
    except OSError:
        return False


def _is_mounted(mount_path: str) -> bool:
    mount_path = os.path.realpath(mount_path.strip()).rstrip("/")
    # Prefer findmnt for robust matching
    if _require_tool("findmnt"):
        code, stdout, _ = _run_command(["findmnt", "-rno", "TARGET", "--target", mount_path], b"")
        if code == 0:
            targets = [os.path.realpath(t).rstrip("/") for t in stdout.splitlines() if t.strip()]
            if any(t == mount_path for t in targets):
                return True
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as f:
            for line in f:
                # mount point is 5th field in mountinfo
                parts = line.split()
                if len(parts) >= 5:
                    mp = _unescape_mount_path(parts[4])
                    if os.path.realpath(mp).rstrip("/") == mount_path:
                        return True
    except OSError:
        return False
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    mp = _unescape_mount_path(parts[1])
                    if os.path.realpath(mp).rstrip("/") == mount_path:
                        return True
    except OSError:
        return False
    return False


def _unescape_mount_path(path: str) -> str:
    # /proc/self/mountinfo escapes spaces and other chars as octal (e.g., \040)
    def repl(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 8))
        except ValueError:
            return match.group(0)

    return re.sub(r"\\([0-7]{3})", repl, path)


def _require_tool(tool: str) -> Optional[str]:
    return shutil.which(tool)


def _run_command(cmd: list[str], stdin_data: bytes) -> tuple[int, str, str]:
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    stdout, stderr = proc.communicate(stdin_data)
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def _extract_master_key(output: str) -> Optional[str]:
    for line in output.splitlines():
        if "MasterKey" in line:
            return line.strip()
    return None


def _validate_duration(value: str) -> bool:
    # Accept values like "0", "500s", "2h45m", "30m", "1.5h"
    return value == "0" or bool(re.fullmatch(r"\d+(?:\.\d+)?[smhd](?:\d+(?:\.\d+)?[smhd])*", value))


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>gocryptfs Manager</title>
  <style>
    :root {
      --bg: #f3efe6;
      --panel: #fffcf6;
      --text: #1f2a2c;
      --muted: #5f6c72;
      --line: #d9d0bc;
      --accent: #0f7a70;
      --accent-2: #cc8b2c;
      --error: #9f1f1f;
      color-scheme: light;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 10% 5%, rgba(204, 139, 44, 0.12), transparent 35%),
        radial-gradient(circle at 90% 0%, rgba(15, 122, 112, 0.16), transparent 35%),
        var(--bg);
      padding: 22px;
    }
    .container { max-width: 1020px; margin: 0 auto; }
    h1 { margin: 0 0 8px; font-size: 2rem; letter-spacing: 0.2px; }
    h2 { margin: 0 0 10px; font-size: 1.2rem; }
    .subtitle { color: var(--muted); margin: 0 0 18px; }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      box-shadow: 0 12px 35px rgba(37, 34, 23, 0.08);
      padding: 16px;
      margin-bottom: 16px;
    }
    .row { display: flex; gap: 12px; flex-wrap: wrap; }
    .row > div { flex: 1 1 240px; }
    label { display: block; margin: 8px 0 4px; font-weight: 600; }
    input[type="text"], input[type="password"], textarea, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 9px 10px;
      font: inherit;
      background: #fffdf8;
      color: var(--text);
    }
    textarea { min-height: 68px; resize: vertical; }
    .controls {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 10px;
      align-items: center;
    }
    button {
      border: 0;
      border-radius: 8px;
      background: var(--accent);
      color: #fff;
      padding: 10px 14px;
      font: inherit;
      font-weight: 600;
      cursor: pointer;
    }
    button.secondary { background: #58656b; }
    button.warm { background: var(--accent-2); }
    .hint { color: var(--muted); font-size: 0.9rem; margin-top: 4px; }
    .checkgrid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 6px 10px;
      margin-top: 8px;
    }
    .checkgrid label { font-weight: 500; margin: 0; display: flex; gap: 6px; align-items: center; }
    .flag-label { display: inline-flex; align-items: center; gap: 6px; }
    .tip {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      height: 18px;
      border-radius: 50%;
      background: #d7cfbb;
      color: #374247;
      font-size: 0.72rem;
      font-weight: 700;
      cursor: help;
      position: relative;
      user-select: none;
      flex: 0 0 18px;
    }
    .tip::after {
      content: attr(data-tip);
      position: absolute;
      left: 50%;
      bottom: calc(100% + 9px);
      transform: translateX(-50%);
      min-width: 200px;
      max-width: min(340px, 75vw);
      padding: 8px 10px;
      border-radius: 8px;
      border: 1px solid #cfc1a5;
      background: #fff8ea;
      color: #1f2a2c;
      font-size: 0.82rem;
      font-weight: 500;
      line-height: 1.35;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
      opacity: 0;
      visibility: hidden;
      transition: opacity 120ms ease;
      pointer-events: none;
      z-index: 40;
    }
    .tip::before {
      content: "";
      position: absolute;
      left: 50%;
      bottom: calc(100% + 3px);
      transform: translateX(-50%);
      border-width: 6px 6px 0 6px;
      border-style: solid;
      border-color: #fff8ea transparent transparent transparent;
      opacity: 0;
      visibility: hidden;
      transition: opacity 120ms ease;
      pointer-events: none;
      z-index: 41;
    }
    .tip:hover::after, .tip:hover::before, .tip:focus-visible::after, .tip:focus-visible::before {
      opacity: 1;
      visibility: visible;
    }
    .status { margin-top: 8px; font-weight: 700; }
    .ok { color: #0f6d32; }
    .err { color: var(--error); }
    pre {
      background: #f6f2e8;
      border: 1px solid #e3d8c2;
      border-radius: 8px;
      padding: 10px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      margin: 8px 0 0;
    }
    .hidden { display: none; }
    @media (max-width: 760px) { body { padding: 12px; } }
  </style>
</head>
<body>
  <div class="container">
    <h1>gocryptfs Manager</h1>
    <p class="subtitle">Local-only UI for init, mount, info, and unmount. Use absolute paths. Secrets are not persisted server-side.</p>

    <div class="card">
      <h2>Init</h2>
      <div class="row">
        <div>
          <label>Encrypted folder (absolute path)</label>
          <input id="init-enc" type="text" placeholder="/home/user/secure.enc" />
          <button type="button" onclick="pickPath('init-enc')">Pick folder</button>
          <div class="hint">The picker fills an absolute path (uses a native dialog).</div>
        </div>
        <div>
          <label>Password</label>
          <input id="init-pass" type="password" />
        </div>
        <div>
          <label>Confirm Password</label>
          <input id="init-pass2" type="password" />
        </div>
      </div>
      <button onclick="initFolder()">Initialize</button>
      <div id="init-status" class="status"></div>
      <pre id="init-output"></pre>
    </div>

    <div class="card">
      <h2>Mount</h2>
      <div class="row">
        <div>
          <label>Encrypted folder (absolute path)</label>
          <input id="mount-enc" type="text" placeholder="/home/user/secure.enc" />
          <button type="button" onclick="pickPath('mount-enc')">Pick folder</button>
        </div>
        <div>
          <label>Mount point (absolute path)</label>
          <input id="mount-point" type="text" placeholder="/home/user/secure.mount" />
          <button type="button" onclick="pickPath('mount-point')">Pick folder</button>
        </div>
        <div>
          <label>Unlock method</label>
          <select id="mount-auth" onchange="toggleAuthFields()">
            <option value="password">Password</option>
            <option value="masterkey">Master Key</option>
          </select>
          <div class="hint">Master key mode uses <code>-masterkey=stdin</code> (safer than command-line key).</div>
        </div>
      </div>
      <div class="row">
        <div id="password-wrap">
          <label>Password</label>
          <input id="mount-pass" type="password" />
        </div>
        <div id="masterkey-wrap" class="hidden">
          <label>Master key</label>
          <textarea id="mount-masterkey" placeholder="6f717d8b-..."></textarea>
        </div>
      </div>
      <div class="checkgrid">
        <label>
          <input id="opt-ro" type="checkbox" />
          <span class="flag-label">Read-only (-ro) <span class="tip" tabindex="0" data-tip="Mount as read-only. File writes, deletes, and renames through this mount are blocked.">?</span></span>
        </label>
        <label>
          <input id="opt-allow-other" type="checkbox" />
          <span class="flag-label">Allow other users (-allow_other) <span class="tip" tabindex="0" data-tip="Allows users other than the mounter to access the mount, subject to permissions. Requires user_allow_other in /etc/fuse.conf.">?</span></span>
        </label>
        <label>
          <input id="opt-sharedstorage" type="checkbox" />
          <span class="flag-label">Shared storage (-sharedstorage) <span class="tip" tabindex="0" data-tip="Improves behavior when multiple gocryptfs instances access the same backing data. Can reduce performance and disables hard-link creation.">?</span></span>
        </label>
        <label>
          <input id="opt-reverse" type="checkbox" />
          <span class="flag-label">Reverse mode (-reverse) <span class="tip" tabindex="0" data-tip="Shows an encrypted read-only view of a plaintext directory. Usually needed only for reverse-mode filesystems.">?</span></span>
        </label>
        <label>
          <input id="opt-aessiv" type="checkbox" />
          <span class="flag-label">AES-SIV (-aessiv) <span class="tip" tabindex="0" data-tip="Use AES-SIV content encryption. Safer with deterministic nonces; generally slower than AES-GCM.">?</span></span>
        </label>
        <label>
          <input id="opt-plaintextnames" type="checkbox" />
          <span class="flag-label">Plaintext names (-plaintextnames) <span class="tip" tabindex="0" data-tip="Do not encrypt file names or symlink targets. This leaks file and folder names and lowers privacy.">?</span></span>
        </label>
        <label>
          <input id="opt-xchacha" type="checkbox" />
          <span class="flag-label">XChaCha20-Poly1305 (-xchacha) <span class="tip" tabindex="0" data-tip="Use XChaCha20-Poly1305 for file content encryption. Often faster on CPUs without AES acceleration.">?</span></span>
        </label>
      </div>
      <div class="row">
        <div>
          <label>Idle timeout (optional, example: 30m) <span class="tip" tabindex="0" data-tip="Auto-unmount when idle for this duration (-idle). Use 0 to disable auto-unmount. Open files or a process cwd inside the mount can keep it active.">?</span></label>
          <input id="opt-idle" type="text" placeholder="0, 30m, 2h45m" />
        </div>
        <div>
          <label>Kernel mount options (optional, -ko) <span class="tip" tabindex="0" data-tip="Comma-separated options passed to the kernel FUSE mount layer, for example noexec,dev,suid.">?</span></label>
          <input id="opt-ko" type="text" placeholder="noexec,dev,suid" />
        </div>
      </div>
      <button onclick="mountFolder()">Mount</button>
      <div id="mount-status" class="status"></div>
      <pre id="mount-output"></pre>
    </div>

    <div class="card">
      <h2>Info</h2>
      <div class="row">
        <div>
          <label>Encrypted folder (absolute path)</label>
          <input id="info-enc" type="text" placeholder="/home/user/secure.enc" />
          <button type="button" class="secondary" onclick="pickPath('info-enc')">Pick folder</button>
        </div>
      </div>
      <div class="controls">
        <button class="warm" onclick="infoFolder()">Show Config Info</button>
      </div>
      <div id="info-status" class="status"></div>
      <pre id="info-output"></pre>
    </div>

    <div class="card">
      <h2>Unmount</h2>
      <div class="row">
        <div>
          <label>Mount point (absolute path)</label>
          <input id="umount-point" type="text" placeholder="/home/user/secure.mount" />
          <button type="button" onclick="pickPath('umount-point')">Pick folder</button>
        </div>
      </div>
      <button onclick="unmountFolder()">Unmount</button>
      <div id="umount-status" class="status"></div>
      <pre id="umount-output"></pre>
    </div>
  </div>

<script>
  function showResult(statusEl, outputEl, data) {
    statusEl.textContent = data.ok ? "Success" : "Error";
    statusEl.className = data.ok ? "status ok" : "status err";
    outputEl.textContent = data.master_key ? (data.master_key + "\\n\\n" + data.output) : (data.output || data.error || "");
  }

  function toggleAuthFields() {
    const mode = document.getElementById("mount-auth").value;
    document.getElementById("password-wrap").classList.toggle("hidden", mode !== "password");
    document.getElementById("masterkey-wrap").classList.toggle("hidden", mode !== "masterkey");
  }

  async function initFolder() {
    const enc = document.getElementById("init-enc").value.trim();
    const p1 = document.getElementById("init-pass").value;
    const p2 = document.getElementById("init-pass2").value;
    const statusEl = document.getElementById("init-status");
    const outputEl = document.getElementById("init-output");
    if (p1 !== p2) {
      showResult(statusEl, outputEl, {ok:false, error:"Passwords do not match."});
      return;
    }
    const res = await fetch("/api/init", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({enc_path: enc, password: p1, password_confirm: p2})
    });
    const data = await res.json();
    showResult(statusEl, outputEl, data);
  }

  async function mountFolder() {
    const enc = document.getElementById("mount-enc").value.trim();
    const mp = document.getElementById("mount-point").value.trim();
    const authMode = document.getElementById("mount-auth").value;
    const pw = document.getElementById("mount-pass").value;
    const masterKey = document.getElementById("mount-masterkey").value.trim();
    const statusEl = document.getElementById("mount-status");
    const outputEl = document.getElementById("mount-output");
    const res = await fetch("/api/mount", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({
        enc_path: enc,
        mount_path: mp,
        auth_mode: authMode,
        password: pw,
        master_key: masterKey,
        read_only: document.getElementById("opt-ro").checked,
        allow_other: document.getElementById("opt-allow-other").checked,
        sharedstorage: document.getElementById("opt-sharedstorage").checked,
        reverse: document.getElementById("opt-reverse").checked,
        aessiv: document.getElementById("opt-aessiv").checked,
        plaintextnames: document.getElementById("opt-plaintextnames").checked,
        xchacha: document.getElementById("opt-xchacha").checked,
        idle_timeout: document.getElementById("opt-idle").value.trim(),
        kernel_options: document.getElementById("opt-ko").value.trim()
      })
    });
    const data = await res.json();
    showResult(statusEl, outputEl, data);
  }

  async function infoFolder() {
    const enc = document.getElementById("info-enc").value.trim();
    const statusEl = document.getElementById("info-status");
    const outputEl = document.getElementById("info-output");
    const res = await fetch("/api/info", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({enc_path: enc})
    });
    const data = await res.json();
    showResult(statusEl, outputEl, data);
  }

  async function unmountFolder() {
    const mp = document.getElementById("umount-point").value.trim();
    const statusEl = document.getElementById("umount-status");
    const outputEl = document.getElementById("umount-output");
    const res = await fetch("/api/unmount", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({mount_path: mp})
    });
    const data = await res.json();
    showResult(statusEl, outputEl, data);
  }

  async function pickPath(targetId) {
    const res = await fetch("/api/pick", {method: "POST"});
    const data = await res.json();
    if (data.ok && data.path) {
      document.getElementById(targetId).value = data.path;
    }
  }

  toggleAuthFields();
</script>
</body>
</html>
"""


@app.post("/api/init")
def init_folder(req: InitRequest) -> JSONResponse:
    req.enc_path = req.enc_path.strip()
    if not _is_abs_path(req.enc_path):
        return JSONResponse({"ok": False, "error": "Encrypted folder path must be an absolute path."})
    if req.password != req.password_confirm:
        return JSONResponse({"ok": False, "error": "Passwords do not match."})
    if _path_exists(req.enc_path):
        conf_path = os.path.join(req.enc_path, "gocryptfs.conf")
        if os.path.exists(conf_path):
            return JSONResponse({"ok": False, "error": "Encrypted folder already initialized."})
        if not _is_dir_empty(req.enc_path):
            return JSONResponse({"ok": False, "error": "Encrypted folder exists and is not empty."})

    if not _require_tool("gocryptfs"):
        return JSONResponse({"ok": False, "error": "gocryptfs is not installed or not in PATH."})

    cmd = ["gocryptfs", "-init", req.enc_path]
    stdin_data = (req.password + "\n" + req.password_confirm + "\n").encode()
    code, stdout, stderr = _run_command(cmd, stdin_data)
    output = stdout.strip()
    if code != 0:
        return JSONResponse({"ok": False, "error": stderr.strip() or output or "Initialization failed.", "output": output})

    master_key = _extract_master_key(output)
    return JSONResponse({"ok": True, "output": output, "master_key": master_key})


@app.post("/api/mount")
def mount_folder(req: MountRequest) -> JSONResponse:
    req.enc_path = req.enc_path.strip()
    req.mount_path = req.mount_path.strip()
    if not _is_abs_path(req.enc_path) or not _is_abs_path(req.mount_path):
        return JSONResponse({"ok": False, "error": "Paths must be absolute."})
    if not _path_exists(req.enc_path):
        return JSONResponse({"ok": False, "error": "Encrypted folder does not exist."})
    if not _path_exists(req.mount_path):
        return JSONResponse({"ok": False, "error": "Mount point does not exist."})
    if not _is_dir_empty(req.mount_path):
        return JSONResponse({"ok": False, "error": "Mount point is not empty."})
    if _is_mounted(req.mount_path):
        return JSONResponse({"ok": False, "error": "Mount point is already mounted."})
    conf_path = os.path.join(req.enc_path, "gocryptfs.conf")
    if req.auth_mode == "password" and not os.path.exists(conf_path):
        return JSONResponse({"ok": False, "error": "Encrypted folder is not initialized."})

    if not _require_tool("gocryptfs"):
        return JSONResponse({"ok": False, "error": "gocryptfs is not installed or not in PATH."})

    if req.auth_mode == "password":
        if not req.password:
            return JSONResponse({"ok": False, "error": "Password is required for password unlock mode."})
    else:
        req.master_key = req.master_key.strip()
        if not req.master_key:
            return JSONResponse({"ok": False, "error": "Master key is required for master-key unlock mode."})

    req.idle_timeout = req.idle_timeout.strip()
    req.kernel_options = req.kernel_options.strip()
    if req.idle_timeout and not _validate_duration(req.idle_timeout):
        return JSONResponse({"ok": False, "error": "Idle timeout format is invalid. Use values like '30m' or '2h45m'."})

    cmd = ["gocryptfs"]
    if req.read_only:
        cmd.append("-ro")
    if req.allow_other:
        cmd.append("-allow_other")
    if req.sharedstorage:
        cmd.append("-sharedstorage")
    if req.reverse:
        cmd.append("-reverse")
    if req.aessiv:
        cmd.append("-aessiv")
    if req.plaintextnames:
        cmd.append("-plaintextnames")
    if req.xchacha:
        cmd.append("-xchacha")
    if req.idle_timeout:
        cmd += ["-idle", req.idle_timeout]
    if req.kernel_options:
        cmd += ["-ko", req.kernel_options]
    if req.auth_mode == "masterkey":
        cmd.append("-masterkey=stdin")
    cmd += [req.enc_path, req.mount_path]

    stdin_data = (req.password + "\n").encode() if req.auth_mode == "password" else (req.master_key + "\n").encode()
    code, stdout, stderr = _run_command(cmd, stdin_data)
    output = stdout.strip()
    if code != 0:
        err = stderr.strip() or "Mount failed."
        return JSONResponse({"ok": False, "error": err, "output": ""})

    return JSONResponse({"ok": True, "output": output or "Mounted successfully."})


@app.post("/api/info")
def info_folder(req: InfoRequest) -> JSONResponse:
    enc_path = req.enc_path.strip()
    if not _is_abs_path(enc_path):
        return JSONResponse({"ok": False, "error": "Encrypted folder path must be absolute."})
    if not _path_exists(enc_path):
        return JSONResponse({"ok": False, "error": "Encrypted folder does not exist."})
    conf_path = os.path.join(enc_path, "gocryptfs.conf")
    if not os.path.exists(conf_path):
        return JSONResponse({"ok": False, "error": "No gocryptfs.conf found in encrypted folder."})
    if not _require_tool("gocryptfs"):
        return JSONResponse({"ok": False, "error": "gocryptfs is not installed or not in PATH."})

    cmd = ["gocryptfs", "-info", enc_path]
    code, stdout, stderr = _run_command(cmd, b"")
    output = stdout.strip()
    if code != 0:
        return JSONResponse({"ok": False, "error": stderr.strip() or "Failed to read config info.", "output": output})
    return JSONResponse({"ok": True, "output": output or "No output from gocryptfs -info."})


@app.post("/api/unmount")
def unmount_folder(req: UnmountRequest) -> JSONResponse:
    req.mount_path = req.mount_path.strip()
    if not _is_abs_path(req.mount_path):
        return JSONResponse({"ok": False, "error": "Mount point path must be absolute."})
    if not _path_exists(req.mount_path):
        return JSONResponse({"ok": False, "error": "Mount point does not exist."})
    if not _is_mounted(req.mount_path):
        return JSONResponse({"ok": False, "error": "Mount point is not mounted."})

    if not _require_tool("fusermount"):
        return JSONResponse({"ok": False, "error": "fusermount is not installed or not in PATH."})

    cmd = ["fusermount", "-u", req.mount_path]
    code, stdout, stderr = _run_command(cmd, b"")
    output = stdout.strip()
    if code != 0:
        err = stderr.strip() or output or "Unmount failed."
        if "busy" in err.lower():
            err = "Unmount failed: mount point is busy (files in use)."
        return JSONResponse({"ok": False, "error": err, "output": ""})

    if _is_mounted(req.mount_path):
        return JSONResponse({"ok": False, "error": "Unmount failed: mount point is still mounted.", "output": ""})

    return JSONResponse({"ok": True, "output": output or "Unmounted successfully."})


@app.post("/api/pick")
def pick_folder() -> JSONResponse:
    # Uses a native dialog via zenity if available (local-only).
    if not _require_tool("zenity"):
        return JSONResponse({"ok": False, "error": "zenity is not installed."})
    cmd = ["zenity", "--file-selection", "--directory", "--title=Select Folder"]
    code, stdout, stderr = _run_command(cmd, b"")
    if code != 0:
        return JSONResponse({"ok": False, "error": "No folder selected."})
    path = stdout.strip()
    if not _is_abs_path(path):
        return JSONResponse({"ok": False, "error": "Selected path is not absolute."})
    return JSONResponse({"ok": True, "path": path})


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
