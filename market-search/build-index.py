#!/usr/bin/env python3
"""Regenerate the browser-ready question index from questions.json."""
import json
from pathlib import Path

root = Path(__file__).resolve().parent
source = root / "data" / "questions.json"
target = root / "data" / "questions.js"
records = json.loads(source.read_text(encoding="utf-8"))
if not isinstance(records, list):
    raise SystemExit("questions.json must contain a JSON array")
required = {"question", "type", "answer"}
for index, record in enumerate(records, start=1):
    if not isinstance(record, dict) or not required.issubset(record):
        raise SystemExit(f"record {index} needs question, type, and answer fields")
target.write_text(
    "window.MARKET_QUESTIONS = "
    + json.dumps(records, ensure_ascii=False, separators=(",", ":"))
    + ";\n",
    encoding="utf-8",
)
print(f"Wrote {len(records)} questions to {target.name}")
