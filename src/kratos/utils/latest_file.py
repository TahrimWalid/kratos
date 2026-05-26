from pathlib import Path
from datetime import datetime

def latest_file(dir_path: Path, pattern: str) -> Path | None:
    files = sorted(dir_path.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def files_in_date_range(
    dir_path: Path, 
    pattern: str, 
    since: str | None = None, 
    until: str | None = None
) -> list[Path]:
    """
    Filter files by date range extracted from filename timestamps.
    
    Filenames should have format: *_YYYYMMDD_HHMMSS.* 
    Example: auth_stats_20260203_104512.json
    
    Args:
        dir_path: Directory to search
        pattern: Glob pattern (e.g., "auth_stats_*.json")
        since: YYYYMMDD format (inclusive)
        until: YYYYMMDD format (inclusive)
    
    Returns:
        Sorted list of matching files in ascending order
    """
    files = sorted(dir_path.glob(pattern), key=lambda p: p.stat().st_mtime)
    
    if not since and not until:
        return files
    
    filtered = []
    for f in files:
        # Extract YYYYMMDD from filename: name_20260203_HHMMSS.ext
        try:
            parts = f.stem.split("_")
            if len(parts) >= 2:
                date_str = parts[-2]  # Second-to-last component is typically the date
                if len(date_str) == 8 and date_str.isdigit():
                    if since and date_str < since:
                        continue
                    if until and date_str > until:
                        continue
                    filtered.append(f)
        except Exception:
            pass
    
    return filtered
