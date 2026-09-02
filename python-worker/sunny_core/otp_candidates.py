from __future__ import annotations

import base64
import hashlib
import html
import json
import quopri
import re
import unicodedata
from html.parser import HTMLParser
from typing import Any
from urllib.parse import unquote


_CODE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
_SEPARATED_CODE = re.compile(r"(?<!\d)(\d(?:[\s\u200b\u200c\u200d\u2060\-_.:/]*\d){5})(?!\d)")
_CONTEXT = re.compile(r"openai|chatgpt|verification|verify|security\s*code|one[- ]time|\botp\b|验证码|校验码|一次性|一時|検証|認証|ログイン.?コード", re.I)
_DIRECT_CONTEXT = re.compile(
    r"(?:verification|security|one[- ]time|login|email|\botp\b|验证码|校验码|一次性|一時|検証|認証|ログイン)"
    r"(?:[\s\S]{0,48}?)(?:code|コード|码)?\s*[:：]?\s*$",
    re.I,
)
_CODE_KEY = re.compile(r"code|otp|verification|verify|验证码", re.I)
_CONTENT_KEY = re.compile(r"body|content|text|html|message|subject|snippet|preview|payload|data|mail", re.I)
_EMAIL_OR_URL = re.compile(r"[\w.+-]*\d{6}[\w.+-]*@|https?://\S*\d{6}|(?:^|\s)(?:from|sender|发件人|差出人)\s*[:：]", re.I)
_DATE_CONTEXT = re.compile(
    r"(?:20\d{2}[-/.年]\d{1,2}[-/.月]\d{1,2}(?:日)?[T\s]+\d{1,2}:\d{2}"
    r"|(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+20\d{2}\s+\d{1,2}:\d{2}"
    r"|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+20\d{2}\s+\d{1,2}:\d{2})",
    re.I,
)
_HTML_CONTENT_MARKER = re.compile(r"(?:^|[-_\s])(body|content|message|mail[-_]?body|email[-_]?body|letter)(?:$|[-_\s])", re.I)
_HTML_META_MARKER = re.compile(r"(?:^|[-_\s])(meta|sender|from|date|time|header)(?:$|[-_\s])", re.I)
_HTML_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


class _MailHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[dict[str, Any]] = []
        self.contents: list[dict[str, str]] = []
        self.text_nodes: list[dict[str, str]] = []
        self.subjects: list[str] = []
        self.dates: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {str(key).lower(): str(value or "") for key, value in attrs}
        marker = " ".join((attributes.get("class", ""), attributes.get("id", ""), attributes.get("role", ""))).strip()
        kind = ""
        if _HTML_CONTENT_MARKER.search(marker):
            kind = "content"
        elif re.search(r"(?:^|[-_\s])subject(?:$|[-_\s])", marker, re.I):
            kind = "subject"
        elif re.search(r"(?:^|[-_\s])date(?:$|[-_\s])", marker, re.I):
            kind = "date"
        elif _HTML_META_MARKER.search(marker):
            kind = "meta"
        node = {"tag": tag.lower(), "kind": kind, "text": ""}
        if node["tag"] not in _HTML_VOID_TAGS:
            self.stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() not in _HTML_VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        target = tag.lower()
        index = next((i for i in range(len(self.stack) - 1, -1, -1) if self.stack[i]["tag"] == target), -1)
        if index < 0:
            return
        closed = self.stack[index:]
        del self.stack[index:]
        for node in closed:
            text = re.sub(r"\s+", " ", node["text"]).strip()
            if not text:
                continue
            if node["kind"] == "content":
                self.contents.append({"text": text})
            elif node["kind"] == "subject":
                self.subjects.append(text)
            elif node["kind"] == "date":
                self.dates.append(text)

    def handle_data(self, data: str) -> None:
        if not data:
            return
        if any(node["tag"] in {"script", "style"} for node in self.stack):
            return
        text = re.sub(r"\s+", " ", data).strip()
        if text:
            tag_path = ".".join(node["tag"] for node in self.stack[-4:]) or "root"
            self.text_nodes.append({"text": text, "path": tag_path})
        for node in self.stack:
            node["text"] += f" {data}"


def _html_content_sources(value: str) -> list[tuple[str, str]]:
    if "<" not in value or ">" not in value:
        return []
    parser = _MailHTMLParser()
    try:
        parser.feed(value)
        parser.close()
    except Exception:
        return []
    document_text = " ".join(item["text"] for item in parser.text_nodes)
    detected_date = next((match.group(0) for match in _DATE_CONTEXT.finditer(document_text)), "")
    identity = "|".join([*(parser.subjects[:1]), *(parser.dates[:1]), detected_date])
    identity_key = _fingerprint(identity) if identity else "unknown"
    sources = [
        (f"$.html.message_body[{index}].{identity_key}", item["text"])
        for index, item in enumerate(parser.contents)
    ]
    sources.extend(
        (f"$.html.text[{index}].{item['path']}.{identity_key}", item["text"])
        for index, item in enumerate(parser.text_nodes)
    )
    return sources


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _text_variants(value: str) -> list[str]:
    raw = str(value or "")
    variants = [raw]
    if re.search(r"\\u[0-9a-fA-F]{4}|\\/", raw):
        decoded = re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), raw).replace("\\/", "/")
        if decoded and decoded != raw:
            variants.append(decoded)
    for decoded in (unquote(raw), quopri.decodestring(raw.encode("utf-8")).decode("utf-8", errors="replace")):
        if decoded and decoded not in variants:
            variants.append(decoded)
    compact = re.sub(r"\s+", "", raw)
    if len(compact) >= 24 and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        try:
            decoded = base64.b64decode(compact, validate=True).decode("utf-8")
            if decoded:
                variants.append(decoded)
        except Exception:
            pass
    return variants


def _collect(value: Any, path: str, output: list[tuple[str, str]]) -> None:
    if isinstance(value, str):
        output.append((path, value))
    elif isinstance(value, int) and 100000 <= value <= 999999 and _CODE_KEY.search(path):
        output.append((path, str(value)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _collect(item, f"{path}[{index}]", output)
    elif isinstance(value, dict):
        for key, item in value.items():
            _collect(item, f"{path}.{key}", output)


def _overlaps_date(value: str, start: int, end: int) -> bool:
    return any(match.start() < end and match.end() > start for match in _DATE_CONTEXT.finditer(value))


def extract_otp_candidates(raw: str) -> list[dict[str, Any]]:
    value = str(raw or "")
    sources: list[tuple[str, str]] = [("$raw", value)]
    sources.extend(_html_content_sources(value))
    for index, match in enumerate(re.finditer(r"(?is)<script\b[^>]*>(.*?)</script\s*>", value)):
        script = html.unescape(match.group(1) or "")
        if script.strip():
            sources.append((f"$.script[{index}]", script))
    for index, match in enumerate(re.finditer(r"(?is)\b(?:data|value|content|title|aria-label)\s*=\s*(['\"])(.*?)\1", value)):
        attribute = html.unescape(match.group(2) or "")
        if attribute.strip():
            sources.append((f"$.attribute[{index}]", attribute))
    try:
        _collect(json.loads(value), "$", sources)
    except Exception:
        pass
    found: dict[str, dict[str, Any]] = {}
    for source_index, (path, source) in enumerate(sources):
        for variant in _text_variants(source):
            normalized = html.unescape(variant)
            normalized = re.sub(r"(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)>", " ", normalized)
            normalized = re.sub(r"(?s)<[^>]+>", " ", normalized)
            for match in _CODE.finditer(normalized):
                if _overlaps_date(normalized, match.start(), match.end()):
                    continue
                code = "".join(str(unicodedata.digit(char)) if char.isdigit() else char for char in match.group(1))
                start, end = max(0, match.start() - 120), min(len(normalized), match.end() + 120)
                context = re.sub(r"\s+", " ", normalized[start:end]).strip()
                score = (40 if _CONTEXT.search(context) else 0) + (40 if _CODE_KEY.search(path) else 0)
                score += 35 if _CONTENT_KEY.search(path) else 0
                prefix = re.sub(r"\s+", " ", normalized[max(0, match.start() - 80):match.start()])
                score += 80 if _DIRECT_CONTEXT.search(prefix) else 0
                score -= 120 if _EMAIL_OR_URL.search(context) else 0
                score += 30 if normalized.strip() == match.group(1) else 0
                score -= min(source_index, 20) * 0.01
                key = _fingerprint(f"{code}|{path}|{context}")
                candidate = {"code": code, "key": key, "score": score}
                if key not in found or score > found[key]["score"]:
                    found[key] = candidate
            for match in _SEPARATED_CODE.finditer(normalized):
                if _CODE.fullmatch(match.group(1)):
                    continue
                if _overlaps_date(normalized, match.start(), match.end()):
                    continue
                digits = "".join(str(unicodedata.digit(char)) for char in match.group(1) if char.isdigit())
                if len(digits) != 6:
                    continue
                start, end = max(0, match.start() - 120), min(len(normalized), match.end() + 120)
                context = re.sub(r"\s+", " ", normalized[start:end]).strip()
                score = (40 if _CONTEXT.search(context) else 0) + (40 if _CODE_KEY.search(path) else 0) - 5
                score += 35 if _CONTENT_KEY.search(path) else 0
                prefix = re.sub(r"\s+", " ", normalized[max(0, match.start() - 80):match.start()])
                score += 80 if _DIRECT_CONTEXT.search(prefix) else 0
                score -= 120 if _EMAIL_OR_URL.search(context) else 0
                score -= min(source_index, 20) * 0.01
                key = _fingerprint(f"{digits}|{path}|{context}")
                candidate = {"code": digits, "key": key, "score": score}
                if key not in found or score > found[key]["score"]:
                    found[key] = candidate
    return sorted(found.values(), key=lambda item: item["score"], reverse=True)
