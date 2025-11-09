#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract crypto keys from ExLoader logs")
    parser.add_argument("log", type=Path, help="Path to JSONL log")
    parser.add_argument("--algorithm", type=str, default=None,
                        help="Filter by algorithm (e.g., AES-256)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.log.exists():
        print(f"Log file {args.log} not found", file=sys.stderr)
        sys.exit(1)

    with args.log.open("r", encoding="utf-8") as infile:
        for line in infile:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("type") == "crypto.encrypt" and "key" in entry:
                alg = entry["key"].get("algorithm")
                if args.algorithm and alg != args.algorithm:
                    continue
                print(json.dumps(entry["key"], indent=2))



if __name__ == "__main__":
    main()
