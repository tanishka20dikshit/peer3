#!/usr/bin/env python3
import argparse, json
from pathlib import Path
import bcrypt

DB_PATH = Path(__file__).resolve().parent / "../../data/user-keys.json"

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--user", required=True, help="username (e.g. ella)")
    p.add_argument("--password", required=True, help="new plaintext password")
    args = p.parse_args()

    db = json.loads(DB_PATH.read_text())
    users = db.get("users", {})
    target = None
    for uuid, info in users.items():
        if info.get("name") == args.user:
            target = (uuid, info); break
    if not target:
        raise SystemExit(f"user '{args.user}' not found in {DB_PATH}")

    hashed = bcrypt.hashpw(args.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    users[target[0]]["pwd_hash"] = hashed
    tmp = DB_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(db, indent=2, ensure_ascii=False))
    tmp.replace(DB_PATH)
    print(f"✅ updated pwd_hash for {args.user}")

if __name__ == "__main__":
    main()
