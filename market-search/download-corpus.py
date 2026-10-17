#!/usr/bin/env python3
"""Download the SAMR market-regulation law corpus and build an offline text index.

The script fetches the official database's complete public search result set,
downloads available source PDFs, extracts their text with pypdf, and writes a
browser-ready data file. Run it manually when refreshing the offline corpus.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from threading import Lock
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import json
import logging
import re
import time

try:
    from pypdf import PdfReader
except ImportError as exc:
    raise SystemExit("pypdf is required to build the searchable text index") from exc
logging.getLogger("pypdf").setLevel(logging.ERROR)

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
PDF_DIR = DATA / "laws"
BASE = "https://sjfg.samr.gov.cn/law/"
LIST_ENDPOINT = BASE + "law_search/getLawStore.do"
DETAIL_ENDPOINT = BASE + "law_search/queryLawByLawId.do"
PDF_DOWNLOAD_ENDPOINT = BASE + "law_search/downLoadPdfFile.do"
FILE_BASE = BASE + "file/"
FALLBACK_OFFICIAL_PDFS = {
    "cbdb8221a5f248349fc103967d4b8585": "https://www.cnipa.gov.cn/attach/0/d8f9d166b94649a6bd540c3a95e3595e.pdf",
}
SUPPLEMENTAL_CNIPA_RULE = {
    "id": "cnipa-2023-77",
    "title": "规范申请专利行为的规定（2023）",
    "category": "知识产权",
    "validLevel": "部门规章",
    "timeValidCode": 2001,
    "validity": "现行有效",
    "validitySource": "国家知识产权局令第77号",
    "startTime": "2024-01-20",
    "publishedTime": "2023-12-21",
    "source": "国家知识产权局官方文件",
    "sourceUrl": "https://www.cnipa.gov.cn/art/2023/12/21/art_99_189201.html",
    "officialPdfUrl": "https://www.cnipa.gov.cn/attach/0/e20c78eb9eec4319bda189dcfce009d4.pdf",
}
PAGE_SIZE = 600
REQUEST_GAP_SECONDS = 0.12
_last_request = 0.0
_request_lock = Lock()


def open_url(url, data=None, content_type=None, retries=3):
    global _last_request
    headers = {"User-Agent": "SimplerForensic offline corpus downloader/1.0"}
    if content_type:
        headers["Content-Type"] = content_type
    for attempt in range(retries):
        with _request_lock:
            wait = REQUEST_GAP_SECONDS - (time.monotonic() - _last_request)
            if wait > 0:
                time.sleep(wait)
            _last_request = time.monotonic()
        try:
            request = Request(url, data=data, headers=headers)
            with urlopen(request, timeout=45) as response:
                return response.read()
        except (HTTPError, URLError, TimeoutError) as exc:
            if attempt + 1 == retries:
                raise RuntimeError(f"request failed: {url}: {exc}") from exc
            time.sleep(1.0 + attempt)


def post_form(url, values):
    return open_url(url, urlencode(values).encode("utf-8"), "application/x-www-form-urlencoded").decode("utf-8")


def fetch_listing(page_no):
    raw = post_form(LIST_ENDPOINT, {
        "pageNo": str(page_no),
        "pageSize": str(PAGE_SIZE),
        "limit": str(PAGE_SIZE),
        "searchScope": "标题+正文",
        "searchType": "模糊查询",
        "timeValid": "",
        "lawType": "",
        "validLevel": "",
        "lawName": "",
    })
    return json.loads(raw)


def clean_html(text):
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text or "")
    text = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>|</h[1-6]>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = unescape(text).replace("\xa0", " ").replace("\u3000", " ")
    lines = [re.sub(r"[ \t\f\v]+", " ", line).strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def fetch_one(row):
    law_id, title = row[0], row[1]
    result = {
        "id": law_id,
        "title": title,
        "validLevel": row[2] or "",
        "timeValidCode": row[3],
        "validity": {2001: "现行有效", 2002: "尚未生效"}.get(row[3], "数据库未标注"),
        "category": row[4] or "未分类",
        "startTime": row[5] or "",
        "publishedTime": row[7] or "",
        "source": "国家市场监督管理总局市场监管法律法规规章数据库",
        "sourceUrl": f"https://sjfg.samr.gov.cn/law/pageInfo/law_search_new.law_details?lawId={law_id}&lawName=&label=0&beforeUrl=index",
        "text": "",
        "pdf": "",
        "downloadError": "",
    }
    try:
        detail = json.loads(open_url(DETAIL_ENDPOINT, json.dumps({"id": law_id}).encode("utf-8"), "application/json"))
        metadata = detail.get("page") or {}
        result.update({
            "title": metadata.get("lawName") or title,
            "validLevel": metadata.get("validLevel") or result["validLevel"],
            "timeValidCode": metadata.get("timeValid", result["timeValidCode"]),
            "validity": {2001: "现行有效", 2002: "尚未生效"}.get(metadata.get("timeValid", result["timeValidCode"]), "数据库未标注"),
            "category": metadata.get("lawType") or result["category"],
            "startTime": metadata.get("startTime") or result["startTime"],
            "publishedTime": metadata.get("pubTime") or result["publishedTime"],
        })
        path = metadata.get("filePath") or ""
        pdf_bytes = b""
        if path:
            pdf_bytes = open_url(FILE_BASE + path.lstrip("/"))
        if not pdf_bytes.startswith(b"%PDF") and law_id in FALLBACK_OFFICIAL_PDFS:
            pdf_bytes = open_url(FALLBACK_OFFICIAL_PDFS[law_id])
            result["sourceUrl"] = FALLBACK_OFFICIAL_PDFS[law_id]
            result["source"] = "国家知识产权局官方文件"
        if not pdf_bytes.startswith(b"%PDF"):
            response = open_url(PDF_DOWNLOAD_ENDPOINT, urlencode({"lawId": law_id}).encode("utf-8"), "application/x-www-form-urlencoded")
            if response.startswith(b"%PDF"):
                pdf_bytes = response
        if pdf_bytes.startswith(b"%PDF"):
            PDF_DIR.mkdir(parents=True, exist_ok=True)
            pdf_path = PDF_DIR / f"{law_id}.pdf"
            pdf_path.write_bytes(pdf_bytes)
            result["pdf"] = f"data/laws/{law_id}.pdf"
            try:
                reader = PdfReader(str(pdf_path), strict=False)
                result["text"] = "\n".join((page.extract_text() or "") for page in reader.pages).strip()
            except Exception as exc:
                result["downloadError"] = f"PDF 已下载，文本提取失败：{exc}"
        else:
            result["downloadError"] = "官方条目未提供可识别的 PDF 文件"
    except Exception as exc:
        result["downloadError"] = str(exc)
    return result


def apply_official_corrections_and_supplements(results):
    PDF_DIR.mkdir(parents=True, exist_ok=True)
    for item in results:
        if item["id"] == "cbdb8221a5f248349fc103967d4b8585":
            item["validity"] = "已废止"
            item["validitySource"] = "国家知识产权局令第77号第十三条明确废止"

    item = dict(SUPPLEMENTAL_CNIPA_RULE)
    pdf_bytes = open_url(item.pop("officialPdfUrl"))
    if pdf_bytes.startswith(b"%PDF"):
        pdf_path = PDF_DIR / f"{item['id']}.pdf"
        pdf_path.write_bytes(pdf_bytes)
        item["pdf"] = f"data/laws/{pdf_path.name}"
        item["text"] = "\n".join((page.extract_text() or "") for page in PdfReader(str(pdf_path), strict=False).pages).strip()
        item["downloadError"] = "" if item["text"] else "PDF 已下载，但未能提取可检索文字"
    else:
        item["pdf"] = ""
        item["text"] = ""
        item["downloadError"] = "国家知识产权局官方 PDF 下载失败"
    results.append(item)


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    first = fetch_listing(1)
    total = int(first.get("page", {}).get("count", 0))
    page_size = int(first.get("page", {}).get("pageSize", PAGE_SIZE)) or PAGE_SIZE
    rows = list(first.get("page", {}).get("result", []))
    page_count = (total + page_size - 1) // page_size
    for page_no in range(2, page_count + 1):
        page = fetch_listing(page_no)
        rows.extend(page.get("page", {}).get("result", []))
        if page_no % 20 == 0:
            print(f"Retrieved listing page {page_no}/{page_count}", flush=True)
    unique_rows = {row[0]: row for row in rows if row and row[0]}
    rows = list(unique_rows.values())
    print(f"Official database returned {total} entries; downloading {len(rows)} unique records.", flush=True)

    results = []
    failures = 0
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(fetch_one, row) for row in rows]
        for index, future in enumerate(as_completed(futures), start=1):
            record = future.result()
            results.append(record)
            if record["downloadError"]:
                failures += 1
            if index % 25 == 0 or index == len(rows):
                print(f"Processed {index}/{len(rows)}; download/text issues: {failures}", flush=True)

    apply_official_corrections_and_supplements(results)
    results.sort(key=lambda item: (item["category"], item["title"], item["id"]))
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest = {
        "source": "https://sjfg.samr.gov.cn/law/pageInfo/main.main",
        "fetchedAtUtc": fetched_at,
        "databaseResultCount": total,
        "supplementalCount": 1,
        "recordCount": len(results),
        "pdfCount": sum(bool(item["pdf"]) for item in results),
        "textCount": sum(bool(item["text"]) for item in results),
        "issueCount": failures,
        "records": results,
    }
    (DATA / "laws-full.json").write_text(json.dumps(manifest, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    browser_records = [{key: item.get(key, "") for key in ("id", "title", "category", "validLevel", "timeValidCode", "validity", "validitySource", "startTime", "publishedTime", "source", "sourceUrl", "pdf", "text")} for item in results]
    (DATA / "laws-full.js").write_text("window.MARKET_FULL_LAWS = " + json.dumps(browser_records, ensure_ascii=False, separators=(",", ":")) + ";\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in manifest.items() if key != "records"}, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
