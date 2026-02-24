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
from typing import Optional

from fastapi import FastAPI, HTTPException
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
    password: str


class UnmountRequest(BaseModel):
    mount_path: str = Field(..., description="Absolute path to mount point")


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


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>gocryptfs WebUI (Local)</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 20px; background: #f6f7fb; }
    h1 { margin-bottom: 4px; }
    .container { max-width: 900px; margin: 0 auto; }
    .card { background: #fff; padding: 16px; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); margin-bottom: 18px; }
    label { display: block; margin: 8px 0 4px; font-weight: 600; }
    input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 6px; }
    button { margin-top: 10px; padding: 10px 14px; border: 0; border-radius: 6px; background: #1f6feb; color: #fff; cursor: pointer; }
    button:disabled { background: #999; cursor: not-allowed; }
    .row { display: flex; gap: 12px; flex-wrap: wrap; }
    .row > div { flex: 1 1 250px; }
    pre { background: #f0f0f0; padding: 10px; border-radius: 6px; overflow-x: auto; }
    .ok { color: #0a7a2f; font-weight: 600; }
    .err { color: #b00020; font-weight: 600; }
    .hint { color: #555; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>gocryptfs WebUI</h1>
    <p class="hint">Local-only tool. Provide absolute paths. Passwords are never stored.</p>

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
      <div id="init-status"></div>
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
          <label>Password</label>
          <input id="mount-pass" type="password" />
        </div>
      </div>
      <button onclick="mountFolder()">Mount</button>
      <div id="mount-status"></div>
      <pre id="mount-output"></pre>
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
      <div id="umount-status"></div>
      <pre id="umount-output"></pre>
    </div>
  </div>

<script>
  function showResult(statusEl, outputEl, data) {
    statusEl.textContent = data.ok ? "Success" : "Error";
    statusEl.className = data.ok ? "ok" : "err";
    outputEl.textContent = data.master_key ? (data.master_key + "\\n\\n" + data.output) : (data.output || data.error || "");
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
    const pw = document.getElementById("mount-pass").value;
    const statusEl = document.getElementById("mount-status");
    const outputEl = document.getElementById("mount-output");
    const res = await fetch("/api/mount", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({enc_path: enc, mount_path: mp, password: pw})
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
    if not os.path.exists(conf_path):
        return JSONResponse({"ok": False, "error": "Encrypted folder is not initialized."})

    if not _require_tool("gocryptfs"):
        return JSONResponse({"ok": False, "error": "gocryptfs is not installed or not in PATH."})

    cmd = ["gocryptfs", req.enc_path, req.mount_path]
    stdin_data = (req.password + "\n").encode()
    code, stdout, stderr = _run_command(cmd, stdin_data)
    output = stdout.strip()
    if code != 0:
        err = stderr.strip() or "Mount failed."
        return JSONResponse({"ok": False, "error": err, "output": ""})

    return JSONResponse({"ok": True, "output": output or "Mounted successfully."})


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
