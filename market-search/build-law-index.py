#!/usr/bin/env python3
"""Rebuild the browser-loaded full-text index from the downloaded manifest."""
from pathlib import Path
import json

root = Path(__file__).resolve().parent
source = root / "data" / "laws-full.json"
target = root / "data" / "laws-full.js"
manifest = json.loads(source.read_text(encoding="utf-8"))
records = manifest.get("records")
if not isinstance(records, list):
    raise SystemExit("laws-full.json must contain a records array")
keys = ("id", "title", "category", "validLevel", "timeValidCode", "validity", "validitySource", "startTime", "publishedTime", "source", "sourceUrl", "pdf", "text")
browser_records = [{key: item.get(key, "") for key in keys} for item in records]
target.write_text("window.MARKET_FULL_LAWS = " + json.dumps(browser_records, ensure_ascii=False, separators=(",", ":")) + ";\n", encoding="utf-8")
print(f"Wrote {len(records)} full-text records to {target.name}")
