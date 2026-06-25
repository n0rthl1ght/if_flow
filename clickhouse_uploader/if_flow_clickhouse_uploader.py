#!/usr/bin/env python3
import argparse
import datetime as dt
import glob
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def detect_script_dir() -> str:
    candidates = []
    if "__file__" in globals() and __file__:
        candidates.append(__file__)
    if sys.argv and sys.argv[0]:
        candidates.append(sys.argv[0])

    for candidate in candidates:
        if os.path.isabs(candidate):
            path = candidate
        else:
            try:
                path = os.path.abspath(candidate)
            except FileNotFoundError:
                path = candidate
        if path and os.path.exists(path):
            return os.path.dirname(path)

    env_dir = os.environ.get("IF_FLOW_UPLOADER_DIR")
    if env_dir:
        return env_dir

    return os.getcwd()


SCRIPT_DIR = detect_script_dir()
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    return default if raw is None or raw == "" else raw


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def local_today_str() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d")


def split_base_ext(path: str) -> tuple[str, str]:
    base = os.path.basename(path)
    stem, ext = os.path.splitext(base)
    if ext == "":
        return base, ""
    return stem, ext


def has_glob_magic(path: str) -> bool:
    return any(ch in path for ch in "*?[")


def daily_jsonl_paths(base_path: str) -> list[str]:
    if has_glob_magic(base_path):
        return sorted(glob.glob(base_path))

    if os.path.isfile(base_path):
        return [base_path]

    directory = os.path.dirname(base_path) or "."
    if os.path.isdir(base_path):
        return sorted(glob.glob(os.path.join(base_path, "*.jsonl")))

    stem, ext = split_base_ext(base_path)
    m = re.match(r"^(.*)-\d{4}-\d{2}-\d{2}$", stem)
    if m:
        pattern = os.path.join(directory, os.path.basename(base_path))
        return sorted(glob.glob(pattern))
    # Match both the plain daily file and size-rotated chunks like -0001, -0002.
    pattern = os.path.join(directory, f"{stem}-????-??-??*{ext}")
    return sorted(glob.glob(pattern))


def load_state(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            if isinstance(data, dict):
                data.setdefault("files", {})
                return data
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return {"files": {}, "stats": {}}


def save_state(path: str, state: dict) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp_path, path)


def prune_state_files(state: dict, existing_paths: list[str]) -> None:
    files = state.setdefault("files", {})
    existing = set(existing_paths)
    stale = [path for path in files if path not in existing]
    for path in stale:
        del files[path]


def extract_day_from_path(path: str) -> str | None:
    base = os.path.basename(path)
    match = re.search(r"(\d{4}-\d{2}-\d{2})(?:-\d+)?\.jsonl$", base)
    if match:
        return match.group(1)
    return None


def is_plain_daily_file(path: str) -> bool:
    base = os.path.basename(path)
    return re.search(r"\d{4}-\d{2}-\d{2}\.jsonl$", base) is not None


def is_rotated_past_day_file(path: str) -> bool:
    day = extract_day_from_path(path)
    if not day:
        return False
    return day != local_today_str()


def is_rotated_chunk_file(path: str) -> bool:
    base = os.path.basename(path)
    return re.search(r"\d{4}-\d{2}-\d{2}-\d+\.jsonl$", base) is not None


def safe_delete_uploaded_file(path: str, file_state: dict) -> tuple[bool, str]:
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        return False, "missing"

    inode = int(stat.st_ino)
    size = int(stat.st_size)
    tracked_inode = int(file_state.get("inode", 0))
    tracked_offset = int(file_state.get("offset", 0))

    # Refuse cleanup if the producer rotated/recreated the file behind our back.
    if tracked_inode and inode != tracked_inode:
        return False, "inode_changed"
    if tracked_offset != size:
        return False, "size_changed"

    os.remove(path)
    return True, "deleted"


def safe_truncate_uploaded_file(path: str, file_state: dict) -> tuple[dict | None, str]:
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        return None, "missing"

    inode = int(stat.st_ino)
    size = int(stat.st_size)
    tracked_inode = int(file_state.get("inode", 0))
    tracked_offset = int(file_state.get("offset", 0))

    # Only truncate the exact file state that was fully uploaded.
    if tracked_inode and inode != tracked_inode:
        return None, "inode_changed"
    if tracked_offset != size:
        return None, "size_changed"

    with open(path, "r+", encoding="utf-8") as fh:
        fh.truncate(0)

    return {
        "inode": inode,
        "offset": 0,
        "size": 0,
        "updated_at": utc_now_iso(),
    }, "truncated"


def maybe_cleanup_uploaded_file(cfg: dict, path: str, files_state: dict, stats: dict) -> None:
    if cfg["dry_run"]:
        return

    file_state = files_state.get(path, {})
    tracked_offset = int(file_state.get("offset", 0))
    tracked_size = int(file_state.get("size", 0))
    # Cleanup is safe only when the uploader has consumed the full tracked file.
    if tracked_size <= 0 or tracked_offset != tracked_size:
        stats["cleanup_skipped_not_fully_sent_total"] = int(stats.get("cleanup_skipped_not_fully_sent_total", 0)) + 1
        return

    # Rotated chunks are immutable in practice, so deletion is preferred there.
    if cfg["delete_sent_rotated"] and (is_rotated_past_day_file(path) or is_rotated_chunk_file(path)):
        ok, reason = safe_delete_uploaded_file(path, file_state)
        if ok:
            files_state.pop(path, None)
            stats["deleted_files_total"] = int(stats.get("deleted_files_total", 0)) + 1
            print(f"[uploader] deleted uploaded file={path}")
        else:
            stats["cleanup_skipped_total"] = int(stats.get("cleanup_skipped_total", 0)) + 1
            stats[f"cleanup_skipped_{reason}_total"] = int(stats.get(f"cleanup_skipped_{reason}_total", 0)) + 1
            stats["last_cleanup_skip_reason"] = reason
            print(f"[uploader] cleanup skipped file={path} action=delete reason={reason}")
        return

    # The active daily file may still be open by if_flow, so truncation stays opt-in.
    if cfg["truncate_sent_active"] and not is_rotated_past_day_file(path) and is_plain_daily_file(path):
        new_state, reason = safe_truncate_uploaded_file(path, file_state)
        if new_state is not None:
            files_state[path] = new_state
            stats["truncated_files_total"] = int(stats.get("truncated_files_total", 0)) + 1
            print(f"[uploader] truncated uploaded file={path}")
        else:
            stats["cleanup_skipped_total"] = int(stats.get("cleanup_skipped_total", 0)) + 1
            stats[f"cleanup_skipped_{reason}_total"] = int(stats.get(f"cleanup_skipped_{reason}_total", 0)) + 1
            stats["last_cleanup_skip_reason"] = reason
            print(f"[uploader] cleanup skipped file={path} action=truncate reason={reason}")


def clickhouse_insert(url: str, database: str, table: str, username: str,
                      password: str, payload: bytes, timeout_sec: int) -> None:
    query = f"INSERT INTO {database}.{table} FORMAT JSONEachRow"
    full_url = f"{url}?query={urllib.parse.quote(query)}"
    req = urllib.request.Request(full_url, data=payload, method="POST")
    if username:
        credentials = f"{username}:{password}".encode("utf-8")
        import base64
        req.add_header("Authorization", "Basic " + base64.b64encode(credentials).decode("ascii"))
    req.add_header("Content-Type", "application/x-ndjson")
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        if resp.status < 200 or resp.status >= 300:
            raise RuntimeError(f"clickhouse returned status {resp.status}")
        resp.read()


def clickhouse_insert_with_retry(cfg: dict, payload: bytes) -> int:
    attempt = 0
    delay = cfg["retry_backoff_sec"]
    while True:
        attempt += 1
        try:
            clickhouse_insert(
                cfg["clickhouse_url"],
                cfg["database"],
                cfg["table"],
                cfg["username"],
                cfg["password"],
                payload,
                cfg["timeout_sec"],
            )
            return attempt
        except Exception:
            if attempt >= cfg["max_retries"]:
                raise
            time.sleep(delay)
            delay = min(delay * 2, cfg["retry_backoff_max_sec"])


def decode_jsonl_line(line: bytes) -> str:
    return line.decode("utf-8", errors="replace")


def read_batch(path: str, file_state: dict, max_lines: int, max_bytes: int) -> tuple[list[str], int, dict]:
    stat = os.stat(path)
    inode = int(stat.st_ino)
    size = int(stat.st_size)
    offset = int(file_state.get("offset", 0))
    old_inode = int(file_state.get("inode", 0))

    # A new inode usually means producer-side rotation or recreation; restart from 0.
    if old_inode and inode != old_inode:
        offset = 0
    if offset > size:
        offset = 0

    lines: list[str] = []
    next_offset = offset
    total_bytes = 0

    with open(path, "rb") as fh:
        fh.seek(offset)
        while len(lines) < max_lines and total_bytes < max_bytes:
            pos = fh.tell()
            line = fh.readline()
            if line == b"":
                next_offset = fh.tell()
                break
            decoded_line = decode_jsonl_line(line)
            # Skip damaged lines instead of blocking the whole ingest loop on one record.
            try:
                json.loads(decoded_line)
            except Exception:
                next_offset = fh.tell()
                continue
            line_bytes = len(decoded_line.encode("utf-8"))
            if lines and total_bytes + line_bytes > max_bytes:
                fh.seek(pos)
                next_offset = fh.tell()
                break
            lines.append(decoded_line)
            total_bytes += line_bytes
            next_offset = fh.tell()

    new_state = {
        "inode": inode,
        "offset": next_offset,
        "size": size,
        "updated_at": utc_now_iso(),
    }
    return lines, next_offset, new_state


def run_once(cfg: dict) -> dict:
    state = load_state(cfg["state_path"])
    files_state = state.setdefault("files", {})
    stats = state.setdefault("stats", {})
    file_paths = daily_jsonl_paths(cfg["base_path"])
    prune_state_files(state, file_paths)
    sent_lines = 0
    sent_files = 0
    sent_bytes = 0
    attempts_total = 0
    batches_sent = 0
    batches_seen = 0

    # Fairness is per file: each pass uploads a bounded number of batches from every path.
    for path in file_paths:
        file_sent = False
        for _ in range(cfg["max_batches_per_file"]):
            file_state = files_state.get(path, {})
            lines, _, new_file_state = read_batch(path, file_state, cfg["batch_lines"], cfg["batch_bytes"])
            if not lines:
                files_state[path] = new_file_state
                break

            payload = "".join(lines).encode("utf-8")
            batches_seen += 1
            if cfg["dry_run"]:
                attempts = 1
                print(f"[uploader] dry-run file={path} lines={len(lines)} bytes={len(payload)}")
            else:
                attempts = clickhouse_insert_with_retry(cfg, payload)
                print(f"[uploader] uploaded file={path} lines={len(lines)} bytes={len(payload)} attempts={attempts}")
            files_state[path] = new_file_state
            sent_lines += len(lines)
            sent_bytes += len(payload)
            attempts_total += attempts
            batches_sent += 1
            file_sent = True

        if file_sent:
            sent_files += 1

        maybe_cleanup_uploaded_file(cfg, path, files_state, stats)

    state["last_run_at"] = utc_now_iso()
    stats["last_sent_lines"] = sent_lines
    stats["last_sent_files"] = sent_files
    stats["last_sent_bytes"] = sent_bytes
    stats["last_batches_seen"] = batches_seen
    stats["last_batches_sent"] = batches_sent
    stats["last_attempts_total"] = attempts_total
    stats["last_run_at"] = state["last_run_at"]
    stats["runs_total"] = int(stats.get("runs_total", 0)) + 1
    stats["lines_total"] = int(stats.get("lines_total", 0)) + sent_lines
    stats["bytes_total"] = int(stats.get("bytes_total", 0)) + sent_bytes
    save_state(cfg["state_path"], state)
    print(f"[uploader] done files={sent_files} lines={sent_lines} bytes={sent_bytes} batches={batches_sent}")
    return {
        "sent_lines": sent_lines,
        "sent_files": sent_files,
        "sent_bytes": sent_bytes,
        "batches_sent": batches_sent,
        "attempts_total": attempts_total,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Upload if_flow JSONL batches to ClickHouse")
    parser.add_argument("--once", action="store_true", help="Process one pass and exit")
    parser.add_argument("--dry-run", action="store_true", help="Do not send to ClickHouse")
    return parser.parse_args()


def load_config(args: argparse.Namespace) -> dict:
    default_base_path = os.path.join(PROJECT_DIR, "if_flow.jsonl")
    default_state_path = os.path.join(PROJECT_DIR, "clickhouse_uploader", "clickhouse_uploader_state.json")
    return {
        "base_path": env_str("IF_FLOW_JSON_PATH", default_base_path),
        "state_path": env_str("IF_FLOW_UPLOADER_STATE_PATH", default_state_path),
        "clickhouse_url": env_str("CLICKHOUSE_URL", "http://127.0.0.1:8123/"),
        "database": env_str("CLICKHOUSE_DATABASE", "default"),
        "table": env_str("CLICKHOUSE_TABLE", "if_flow"),
        "username": env_str("CLICKHOUSE_USER", ""),
        "password": env_str("CLICKHOUSE_PASSWORD", ""),
        "batch_lines": env_int("IF_FLOW_UPLOADER_BATCH_LINES", 1000),
        "batch_bytes": env_int("IF_FLOW_UPLOADER_BATCH_BYTES", 1048576),
        "max_batches_per_file": env_int("IF_FLOW_UPLOADER_MAX_BATCHES_PER_FILE", 16),
        "poll_sec": env_int("IF_FLOW_UPLOADER_POLL_SEC", 5),
        "timeout_sec": env_int("IF_FLOW_UPLOADER_TIMEOUT_SEC", 10),
        "max_retries": env_int("IF_FLOW_UPLOADER_MAX_RETRIES", 3),
        "retry_backoff_sec": env_int("IF_FLOW_UPLOADER_RETRY_BACKOFF_SEC", 1),
        "retry_backoff_max_sec": env_int("IF_FLOW_UPLOADER_RETRY_BACKOFF_MAX_SEC", 10),
        "delete_sent_rotated": env_bool("IF_FLOW_UPLOADER_DELETE_SENT_ROTATED", False),
        "truncate_sent_active": env_bool("IF_FLOW_UPLOADER_TRUNCATE_SENT_ACTIVE", False),
        "dry_run": args.dry_run or env_bool("IF_FLOW_UPLOADER_DRY_RUN", False),
    }


def main() -> int:
    args = parse_args()
    cfg = load_config(args)

    if args.once:
        run_once(cfg)
        return 0

    while True:
        try:
            run_once(cfg)
        except urllib.error.URLError as exc:
            print(f"[uploader] clickhouse connection error: {exc}", file=sys.stderr)
        except Exception as exc:
            print(f"[uploader] error: {exc}", file=sys.stderr)
        time.sleep(cfg["poll_sec"])


if __name__ == "__main__":
    raise SystemExit(main())
