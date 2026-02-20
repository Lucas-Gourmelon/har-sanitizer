import json
import re
from urllib.parse import urlsplit, urlunsplit

UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
NUM_SEG_RE = re.compile(r"(?<=/)\d+(?=/|$)")

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

HOST_MAP = {}
HOST_COUNTER = 0

IP_MAP = {}
IP_COUNTER = 0


def host_alias(netloc: str) -> str:
    global HOST_COUNTER
    if not netloc:
        return netloc
    if netloc not in HOST_MAP:
        HOST_COUNTER += 1
        HOST_MAP[netloc] = f"HOST_{HOST_COUNTER}"
    return HOST_MAP[netloc]


def ip_alias(ip: str) -> str:
    global IP_COUNTER
    if not ip:
        return ip
    if ip not in IP_MAP:
        IP_COUNTER += 1
        IP_MAP[ip] = f"IP_{IP_COUNTER}"
    return IP_MAP[ip]


def scrub_url(url: str, drop_query=True, host_mode="redact", mask_path_ids=True):
    try:
        parts = urlsplit(url)
        query = "" if drop_query else parts.query

        if host_mode == "alias":
            netloc = host_alias(parts.netloc)
        else:
            netloc = "REDACTED_HOST" if parts.netloc else parts.netloc

        path = parts.path
        if mask_path_ids:
            path = UUID_RE.sub("REDACTED_ID", path)
            path = NUM_SEG_RE.sub("REDACTED_ID", path)

        return urlunsplit((parts.scheme, netloc, path, query, parts.fragment))
    except Exception:
        return url


def scrub_urls_everywhere(obj, drop_query=True, host_mode="redact", mask_path_ids=True):
    if isinstance(obj, dict):
        return {k: scrub_urls_everywhere(v, drop_query, host_mode, mask_path_ids) for k, v in obj.items()}

    if isinstance(obj, list):
        return [scrub_urls_everywhere(x, drop_query, host_mode, mask_path_ids) for x in obj]

    if isinstance(obj, str):
        s = obj.strip()

        # Scrub full URLs
        if s.startswith(("http://", "https://")):
            return scrub_url(s, drop_query, host_mode, mask_path_ids)

        # Scrub standalone IP addresses
        if IPV4_RE.fullmatch(s) or IPV6_RE.fullmatch(s):
            return ip_alias(s) if host_mode == "alias" else "REDACTED_IP"

    return obj


SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie",
    "proxy-authorization", "x-api-key",
    "x-auth-token", "x-csrf-token", "host"
}


def redact_headers(headers, mode):
    if not headers:
        return headers

    if mode == "ultra":
        return [{"name": h.get("name"), "value": "REDACTED"} for h in headers]

    out = []
    for h in headers:
        name = h.get("name")
        lname = (name or "").lower()

        if lname in SENSITIVE_HEADERS or any(k in lname for k in ("auth", "token", "secret", "session", "key", "jwt", "saml", "assertion")):
            out.append({"name": name, "value": "REDACTED"})
        else:
            out.append(h if mode == "debug" else {"name": name, "value": "REMOVED"})
    return out


def redact_cookies(cookies):
    if not cookies:
        return cookies
    return [{"name": "REDACTED_COOKIE", "value": "REDACTED"} for _ in cookies]


def remove_bodies(entry):
    req = entry.get("request", {})
    resp = entry.get("response", {})

    if isinstance(req.get("postData"), dict):
        if "text" in req["postData"]:
            req["postData"]["text"] = "REMOVED"
        if "params" in req["postData"]:
            req["postData"]["params"] = "REMOVED"

    if isinstance(resp.get("content"), dict):
        if "text" in resp["content"]:
            resp["content"]["text"] = "REMOVED"

    entry["request"] = req
    entry["response"] = resp
    return entry


def sanitize_entries(entries, profile):
    host_mode = "alias" if profile == "debug" else "redact"
    out = []

    for e in entries or []:
        req = e.get("request", {})
        resp = e.get("response", {})

        if "url" in req and isinstance(req["url"], str):
            req["url"] = scrub_url(req["url"], drop_query=True, host_mode=host_mode, mask_path_ids=True)

        req["headers"] = redact_headers(req.get("headers"), profile)
        resp["headers"] = redact_headers(resp.get("headers"), profile)

        req["cookies"] = redact_cookies(req.get("cookies"))
        resp["cookies"] = redact_cookies(resp.get("cookies"))

        e["request"] = req
        e["response"] = resp

        if profile != "debug":
            e = remove_bodies(e)
        else:
            # In debug, still remove request bodies (safer), keep response bodies (you can tighten if needed)
            e = remove_bodies(e)

        out.append(e)

    return out


def main(in_path, out_path, profile):
    with open(in_path, "r", encoding="utf-8") as f:
        har = json.load(f)

    host_mode = "alias" if profile == "debug" else "redact"
    har = scrub_urls_everywhere(har, drop_query=True, host_mode=host_mode, mask_path_ids=True)

    entries = har.get("log", {}).get("entries", [])
    if "log" in har and isinstance(har["log"], dict):
        har["log"]["entries"] = sanitize_entries(entries, profile)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(har, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Local HAR sanitizer with profiles (ultra/strict/debug).")
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--profile", choices=["ultra", "strict", "debug"], default="strict")
    args = p.parse_args()

    main(args.input, args.output, args.profile)