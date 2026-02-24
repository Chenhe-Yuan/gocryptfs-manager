# gocryptfs WebUI (Local-Only)

Local-only WebUI for `gocryptfs` on Linux. Uses a Python FastAPI backend to execute system commands on `127.0.0.1:8000`. No database, no password storage, no external exposure.

## Prerequisites
- Linux
- `gocryptfs` in `PATH`
- `fusermount` in `PATH`
- Optional: `zenity` for the native folder picker

## Install (pip)
```bash
pip install -r requirements.txt
```

## Install (conda)
```bash
conda env create -f environment.yml
conda activate gocryptfs-webui
```

## Run
```bash
python3 app.py
```
Open `http://127.0.0.1:8000`.

## Notes
- The folder picker uses `zenity`. If not installed, enter absolute paths manually.
- Paths with spaces are supported.
- Passwords are sent via stdin and never stored or logged.
