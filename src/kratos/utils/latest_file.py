from pathlib import Path

def latest_file(dir_path: Path, pattern: str) -> Path | None:
    files = sorted(dir_path.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None
