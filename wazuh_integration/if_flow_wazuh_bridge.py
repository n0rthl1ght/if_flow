#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import json
import os
import sys
import time
import urllib.parse
import urllib.request


CURSOR_FIELDS = [
    "minute_ts",
    "host",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "proto",
]


def env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    return default if raw is None or raw == "" else raw


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def env_csv(name: str, default: str) -> list[str]:
    raw = env_str(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def ensure_parent(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def load_state(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {"cursor": None, "stats": {}}
    except json.JSONDecodeError:
        return {"cursor": None, "stats": {}}
    if not isinstance(data, dict):
        return {"cursor": None, "stats": {}}
    return data


def save_state(path: str, state: dict) -> None:
    ensure_parent(path)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp_path, path)


def clickhouse_request(url: str, username: str, password: str, query: str, timeout_sec: int) -> bytes:
    full_url = f"{url}?query={urllib.parse.quote(query)}"
    req = urllib.request.Request(full_url, method="GET")
    if username:
        credentials = f"{username}:{password}".encode("utf-8")
        req.add_header("Authorization", "Basic " + base64.b64encode(credentials).decode("ascii"))
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        return resp.read()


def select_rows(cfg: dict, query: str) -> list[dict]:
    raw = clickhouse_request(
        cfg["clickhouse_url"],
        cfg["clickhouse_user"],
        cfg["clickhouse_password"],
        query + " FORMAT JSONEachRow",
        cfg["timeout_sec"],
    )
    rows: list[dict] = []
    for line in raw.splitlines():
        if not line:
            continue
        rows.append(json.loads(line.decode("utf-8")))
    return rows


def sql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def build_query(cfg: dict, state: dict) -> str:
    where_parts = ["record_type = 'final'"]
    cursor = state.get("cursor")
    if cursor:
        cursor_values = [
            str(int(cursor.get("minute_ts", 0))),
            sql_string(str(cursor.get("host", ""))),
            sql_string(str(cursor.get("src_ip", ""))),
            str(int(cursor.get("src_port", 0))),
            sql_string(str(cursor.get("dst_ip", ""))),
            str(int(cursor.get("dst_port", 0))),
            str(int(cursor.get("proto", 0))),
        ]
        where_parts.append(
            "(minute_ts, host, src_ip, src_port, dst_ip, dst_port, proto) > "
            f"({', '.join(cursor_values)})"
        )
    else:
        bootstrap_minutes = env_int("IF_FLOW_WAZUH_BOOTSTRAP_MINUTES", 15)
        cutoff = int(time.time()) - bootstrap_minutes * 60
        where_parts.append(f"minute_ts >= {cutoff}")

    return f"""
SELECT
    minute_ts,
    minute_iso,
    host,
    class,
    direction,
    proto,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    bytes,
    packets,
    connections_effective,
    tcp_seen_without_syn
FROM {cfg['clickhouse_database']}.{cfg['clickhouse_table']}
WHERE {' AND '.join(where_parts)}
ORDER BY minute_ts, host, src_ip, src_port, dst_ip, dst_port, proto
LIMIT {cfg['batch_rows']}
""".strip()


def matches_rule(row: dict, cfg: dict) -> list[dict]:
    alerts: list[dict] = []
    class_name = str(row.get("class", ""))
    direction = str(row.get("direction", ""))
    total_bytes = int(row.get("bytes", 0))
    tcp_seen_without_syn = bool(row.get("tcp_seen_without_syn", False))

    if class_name in cfg["db_classes"]:
        alerts.append({"rule_name": "db_access_detected", "severity": "high"})
    if class_name in cfg["sensitive_classes"]:
        alerts.append({"rule_name": "directory_or_secret_access_detected", "severity": "high"})
    if class_name in cfg["routing_classes"]:
        alerts.append({"rule_name": "routing_or_tunnel_detected", "severity": "medium"})
    if tcp_seen_without_syn:
        alerts.append({"rule_name": "tcp_without_syn_detected", "severity": "medium"})
    if total_bytes >= cfg["bytes_threshold"] and direction in cfg["large_transfer_directions"]:
        alerts.append({"rule_name": "large_transfer_detected", "severity": "medium"})
    return alerts


def build_alert(row: dict, match: dict) -> dict:
    return {
        "integration": "if_flow",
        "emitted_at": utc_now_iso(),
        "rule_name": match["rule_name"],
        "severity": match["severity"],
        "minute_ts": int(row.get("minute_ts", 0)),
        "minute_iso": str(row.get("minute_iso", "")),
        "host": str(row.get("host", "")),
        "class": str(row.get("class", "")),
        "direction": str(row.get("direction", "")),
        "proto": int(row.get("proto", 0)),
        "src_ip": str(row.get("src_ip", "")),
        "src_port": int(row.get("src_port", 0)),
        "dst_ip": str(row.get("dst_ip", "")),
        "dst_port": int(row.get("dst_port", 0)),
        "bytes": int(row.get("bytes", 0)),
        "packets": int(row.get("packets", 0)),
        "connections_effective": int(row.get("connections_effective", 0)),
        "tcp_seen_without_syn": bool(row.get("tcp_seen_without_syn", False)),
    }


def append_alerts(path: str, alerts: list[dict]) -> None:
    if not alerts:
        return
    ensure_parent(path)
    with open(path, "a", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(json.dumps(alert, ensure_ascii=False) + "\n")


def update_cursor_from_row(state: dict, row: dict) -> None:
    state["cursor"] = {field: row.get(field) for field in CURSOR_FIELDS}


def run_once(cfg: dict, state: dict) -> dict:
    rows = select_rows(cfg, build_query(cfg, state))
    emitted: list[dict] = []
    alerts_seen = 0

    for row in rows:
        matches = matches_rule(row, cfg)
        alerts_seen += len(matches)
        for match in matches:
            emitted.append(build_alert(row, match))
        update_cursor_from_row(state, row)

    append_alerts(cfg["alert_path"], emitted)
    state["last_run_at"] = utc_now_iso()
    stats = state.setdefault("stats", {})
    stats["rows_last_run"] = len(rows)
    stats["alerts_last_run"] = len(emitted)
    stats["alerts_seen_last_run"] = alerts_seen
    stats["runs_total"] = int(stats.get("runs_total", 0)) + 1
    stats["alerts_total"] = int(stats.get("alerts_total", 0)) + len(emitted)
    stats["rows_total"] = int(stats.get("rows_total", 0)) + len(rows)
    print(f"[wazuh_bridge] rows={len(rows)} alerts={len(emitted)}")
    return {"rows": len(rows), "alerts": len(emitted)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export selected if_flow events from ClickHouse to Wazuh localfile JSON")
    parser.add_argument("--once", action="store_true", help="Process one batch and exit")
    return parser.parse_args()


def load_config() -> dict:
    return {
        "clickhouse_url": env_str("CLICKHOUSE_URL", "http://127.0.0.1:8123/"),
        "clickhouse_database": env_str("CLICKHOUSE_DATABASE", "default"),
        "clickhouse_table": env_str("CLICKHOUSE_TABLE", "if_flow"),
        "clickhouse_user": env_str("CLICKHOUSE_USER", ""),
        "clickhouse_password": env_str("CLICKHOUSE_PASSWORD", ""),
        "alert_path": env_str("IF_FLOW_WAZUH_ALERT_PATH", "/opt/if_flow/wazuh/if_flow_alerts.jsonl"),
        "state_path": env_str("IF_FLOW_WAZUH_STATE_PATH", "/opt/if_flow/wazuh/wazuh_bridge_state.json"),
        "poll_sec": env_int("IF_FLOW_WAZUH_POLL_SEC", 30),
        "timeout_sec": env_int("IF_FLOW_WAZUH_TIMEOUT_SEC", 10),
        "batch_rows": env_int("IF_FLOW_WAZUH_BATCH_ROWS", 10000),
        "bytes_threshold": env_int("IF_FLOW_WAZUH_BYTES_THRESHOLD", 1048576),
        "db_classes": set(env_csv("IF_FLOW_WAZUH_DB_CLASSES", "postgres,mysql,mssql,oracle,cassandra,cockroachdb")),
        "sensitive_classes": set(env_csv("IF_FLOW_WAZUH_SENSITIVE_CLASSES", "ldap,kerberos,vault,k8s_api")),
        "routing_classes": set(env_csv("IF_FLOW_WAZUH_ROUTING_CLASSES", "wireguard,bgp,bgpd,bfdd,zebra,ospfd,ospf6d,isisd,babeld,pimd,ldpd,nhrpd,eigrpd,fabricd,pathd,staticd")),
        "large_transfer_directions": set(env_csv("IF_FLOW_WAZUH_LARGE_TRANSFER_DIRECTIONS", "out,transit")),
    }


def main() -> int:
    args = parse_args()
    cfg = load_config()
    state = load_state(cfg["state_path"])

    if args.once:
        run_once(cfg, state)
        save_state(cfg["state_path"], state)
        return 0

    while True:
        try:
            run_once(cfg, state)
            save_state(cfg["state_path"], state)
        except Exception as exc:
            print(f"[wazuh_bridge] error: {exc}", file=sys.stderr)
        time.sleep(cfg["poll_sec"])


if __name__ == "__main__":
    raise SystemExit(main())
