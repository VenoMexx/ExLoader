#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze ExLoader JSONL logs")
    parser.add_argument("log", type=Path, help="Path to JSONL log")
    parser.add_argument("--filter", type=str, default=None,
                        help="Filter expression type=crypto.encrypt, module=network.winhttp, etc.")
    parser.add_argument("--count", action="store_true", help="Print counts grouped by type")
    parser.add_argument("--timeline", action="store_true", help="Print timestamp + type per entry")
    return parser.parse_args()


def matches(entry: dict, filt: str) -> bool:
    if not filt:
        return True
    key, _, value = filt.partition("=")
    if not key:
        return True
    return str(entry.get(key)) == value


def main() -> None:
    args = parse_args()
    if not args.log.exists():
        print(f"Log file {args.log} not found", file=sys.stderr)
        sys.exit(1)

    counts = {}
    with args.log.open("r", encoding="utf-8") as infile:
        for line in infile:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not matches(entry, args.filter):
                continue
            if args.count:
                counts[entry.get("type", "unknown")] = counts.get(entry.get("type", "unknown"), 0) + 1
            if args.timeline:
                print(f"{entry.get('ts', '?')} - {entry.get('type', 'unknown')} - {entry.get('api', '')}")
            if not args.count and not args.timeline:
                print(json.dumps(entry, indent=2))

    if args.count:
        for typ, count in sorted(counts.items(), key=lambda item: item[1], reverse=True):
            print(f"{typ}: {count}")


+IF __name__ == "__main__":
+    main()
