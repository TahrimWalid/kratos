"""Parses `systemctl` unit listings into structured records.

Takes the raw lines `systemctl list-units` prints and turns them into
{unit, load, active, sub, description} dicts, then flags the ones that look like
production services (a web server, a database, and so on) — the context a finding
rule uses to decide whether an exposed port is expected or a surprise.
"""
def parse_systemctl_units(raw_lines: list[str]) -> list[dict[str, str]]:
    units = []
    for line in raw_lines:
        s = line.strip()
        if not s:
            continue
        if s.startswith("UNIT "):
            continue
        if s.startswith("Legend:"):
            break  # stop at legend block
        parts = s.split()
        if len(parts) < 5:
            continue
        unit, load, active, sub = parts[0], parts[1], parts[2], parts[3]
        desc = " ".join(parts[4:])
        # Only keep service units (optional, but cleaner)
        if not unit.endswith(".service"):
            continue
        units.append(
            {
                "unit": unit,
                "load": load,
                "active": active,
                "sub": sub,
                "description": desc,
            }
        )
    return units


def detect_production_like_services(units: list[dict[str, str]]) -> list[str]:
    # map of service unit -> friendly label
    targets = {
        "nginx.service": "nginx",
        "apache2.service": "apache",
        "httpd.service": "apache",
        "mysql.service": "mysql",
        "mariadb.service": "mariadb",
        "postgresql.service": "postgresql",
        "redis-server.service": "redis",
        "redis.service": "redis",
        "docker.service": "docker",
    }

    detected: list[str] = []
    for u in units:
        if not isinstance(u, dict):
            continue
        unit = u.get("unit")
        active = u.get("active")
        if active != "active":
            continue
        if unit in targets:
            label = targets[unit]
            if label not in detected:
                detected.append(label)

    return detected
