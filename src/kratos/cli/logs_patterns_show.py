import json
from pathlib import Path
from kratos.utils.latest_file import latest_file

def cmd_logs_patterns_show(args) -> int:
    logs_dir = args.data_dir / "logs"
    path = latest_file(logs_dir, "auth_patterns_*.json")

    if not path:
        print("[KRATOS] No auth_patterns files found.")
        return 1

    data = json.loads(path.read_text())

    print(f"[KRATOS] Latest patterns file: {path.name}")
    print(f"Generated at: {data.get('generated_at')}")
    print(f"Window: {data['params']['window_minutes']} min | Threshold: {data['params']['threshold']}")
    print("Event types:", ", ".join(data["params"]["event_types"]))
    print(f"Bursts detected: {len(data['bursts'])}")

    for b in data["bursts"]:
        line = (
            f" - {b['event_type']}: {b['count']} events "
            f"({b['start']} → {b['end']})"
        )
        print(line)
        if b.get("context_excerpt_file"):
            print(f"   excerpt: data/logs/excerpts/{b['context_excerpt_file']}")

    return 0
