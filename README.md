# gocryptfs Manager (Local-Only)

Local-only Web UI for `gocryptfs` on Linux. Runs a FastAPI backend on `127.0.0.1:8000` and executes local `gocryptfs`/`fusermount` commands.

## Prerequisites
- Linux
- `gocryptfs` in `PATH`
- `fusermount` in `PATH`
- Optional: `zenity` for folder picker dialogs

Quick check:
```bash
which gocryptfs fusermount
```

## Install

### Option 1: pip
```bash
python3 -m pip install -r requirements.txt
```

### Option 2: conda
```bash
conda env create -f environment.yml
conda activate gocryptfs-webui
```

## Run
From this project directory:
```bash
python3 app.py
```

Then open:
```text
http://127.0.0.1:8000
```

## What the UI supports
- Init encrypted directory (`gocryptfs -init`)
- Mount with password unlock
- Mount with master-key unlock (`-masterkey=stdin`)
- Useful mount flags (`-ro`, `-allow_other`, `-sharedstorage`, `-reverse`, `-aessiv`, `-plaintextnames`, `-xchacha`, `-idle`, `-ko`)
- Show config info (`gocryptfs -info`)
- Unmount (`fusermount -u`)

## Notes
- Use absolute paths in the UI.
- Folder picker uses `zenity`; without it, type paths manually.
- Secrets are passed via stdin and are not persisted by the app.
