#!/usr/bin/env python3



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
from urllib.parse import parse_qs, quote_plus, urlencode, urlparse, urlunparse

try:
    import requests
except Exception:
    print("Missing dependency 'requests'. Install with: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except Exception:
    BS4_AVAILABLE = False

# Optional Playwright for desktop/VM only
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

# ----------------------
# Banner (user-provided ASCII, raw string safe)
# ----------------------
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
      This tool is made for pentesting and bug bounty hunting any misusr i am not responsable
"""

# ----------------------
# ANSI color helpers (works in Termux & most terminals)
# ----------------------
CSI = "\033["
RESET = CSI + "0m"
COLORS = {
    "red": CSI + "31m",
    "green": CSI + "32m",
    "yellow": CSI + "33m",
    "blue": CSI + "34m",
    "magenta": CSI + "35m",
    "cyan": CSI + "36m",
    "white": CSI + "37m",
    "light_blue": CSI + "94m",
}

def color_text(text: str, color: str) -> str:
    return (COLORS.get(color, "") + text + RESET)

# ----------------------
# Logging setup (file + console)
# ----------------------
LOG_FILE = "xinjection_final.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

# ----------------------
# Defaults and globals
# ----------------------
USER_AGENT_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16 Safari/605.1.15",
    "curl/7.79.1",
    "xinjection-final/1.0"
]

COMMON_PARAMS = ["q", "s", "search", "id", "page", "term", "query", "text", "input", "name", "url"]
DEFAULT_THREADS = 10
DEFAULT_DELAY = 0.12
DEFAULT_JITTER = 0.25
DEFAULT_TIMEOUT = 10
MAX_RETRIES = 3
MAX_BACKOFF = 25.0

lock = threading.Lock()
SHUTDOWN = False

def handle_shutdown(signum, frame):
    global SHUTDOWN
    SHUTDOWN = True
    logging.warning("Shutdown signal received — finishing in-flight tasks.")
signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

# ----------------------
# Utility functions
# ----------------------
def rand_token(prefix: str = "xinj", length: int = 8) -> str:
    return f"{prefix}_{''.join(random.choices(string.ascii_lowercase + string.digits, k=length))}"

def atomic_write(path: str, data: str):
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:
        logging.exception("atomic_write failed; falling back to normal write")
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)

def load_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

# ----------------------
# Payload generation and variants (safe, tokenized)
# ----------------------
def generate_payload_templates(kind: str, count: int = 6, oob_domain: Optional[str] = None) -> List[str]:
    templates: List[str] = []
    if kind == "xss_harmless":
        for _ in range(count):
            templates.append("<script>console.log('{token}')</script>")
        templates.append("<img src=x onerror=\"console.log('{token}')\">")
        templates.append("<svg onload=\"console.log('{token}')\"></svg>")
        if oob_domain:
            # harmless external reference that allows OOB detection if you control the domain
            templates.append(f"<img src='https://{oob_domain}/{{token}}' />")
    elif kind == "xss_basic":
        templates = ["<script>alert('{token}')</script>", "<img src=x onerror=alert('x')>"][:count]
    elif kind == "sqli_test":
        templates = ["' OR '1'='1' -- ", "' UNION SELECT NULL -- "][:count]
    elif kind == "lfi_test":
        templates = ["../../etc/passwd", "/etc/passwd", "../../windows/win.ini"][:count]
    else:
        for _ in range(count):
            templates.append("{token}")
    # dedupe
    seen = set()
    out = []
    for t in templates:
        if t not in seen:
            out.append(t); seen.add(t)
    return out

def generate_variants_from_template(template: str, token: Optional[str] = None) -> List[Dict]:
    """
    Create safe variants: original (token replaced), url_encoded, double_url, html_escaped, js_escaped.
    Returns list of dicts: {"type": "...", "payload": "..."}
    """
    if token is None:
        token = rand_token()
    try:
        base = template.replace("{token}", token) if "{token}" in template else template + token
    except Exception:
        base = template + token
    variants = []
    try:
        variants.append({"type": "original", "payload": base})
        variants.append({"type": "url_encoded", "payload": quote_plus(base, safe='')})
        variants.append({"type": "double_url", "payload": quote_plus(quote_plus(base, safe=''), safe='')})
        variants.append({"type": "html_escaped", "payload": html.escape(base)})
        js_escaped = base.replace("'", "\\'").replace('"', '\\"')
        variants.append({"type": "js_escaped", "payload": js_escaped})
    except Exception:
        # fallback
        variants = [{"type": "original", "payload": base}]
    # dedupe preserving order
    seen = set()
    uniq = []
    for v in variants:
        if v["payload"] not in seen:
            uniq.append(v); seen.add(v["payload"])
    return uniq

# ----------------------
# Parameter discovery & light scoring
# ----------------------
def quick_fetch(url: str, timeout: int = 5) -> Tuple[Optional[int], str]:
    # light fetch; don't crash on exceptions
    try:
        resp = requests.get(url, headers={"User-Agent": random.choice(USER_AGENT_POOL)}, timeout=timeout)
        return resp.status_code, resp.text or ""
    except Exception:
        return None, ""

def discover_params(url: str, timeout: int = 5) -> List[str]:
    parsed = urlparse(url)
    params = []
    if parsed.query:
        params.extend(list(parse_qs(parsed.query).keys()))
    # attempt to parse HTML forms if bs4 available
    if BS4_AVAILABLE:
        try:
            status, text = quick_fetch(url, timeout)
            if text:
                soup = BeautifulSoup(text, "html.parser")
                for form in soup.find_all("form"):
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            params.append(name)
        except Exception:
            pass
    # fallback to common params
    if not params:
        params = COMMON_PARAMS.copy()
    # unique preserve order
    return [p for i, p in enumerate(params) if p and p not in params[:i]]

# ----------------------
# Robust GET with retries/backoff (legal, polite)
# ----------------------
def robust_get(session: requests.Session, url: str, headers: Dict = None, cookies: Dict = None,
               timeout: int = DEFAULT_TIMEOUT, max_retries: int = MAX_RETRIES) -> Dict:
    attempt = 0
    backoff = 1.0
    while attempt <= max_retries and not SHUTDOWN:
        try:
            r = session.get(url, headers=headers or {}, cookies=cookies or {}, timeout=timeout, allow_redirects=True)
            status = r.status_code
            text = r.text or ""
            if status in (429, 502, 503, 504):
                # transient server condition; retry politely
                logging.debug(f"Transient HTTP {status} for {url} (attempt {attempt})")
                attempt += 1
                time.sleep(backoff)
                backoff = min(MAX_BACKOFF, backoff * 2)
                continue
            return {"status": status, "text": text}
        except requests.exceptions.Timeout as e:
            logging.debug(f"Timeout {e} for {url} (attempt {attempt})")
            attempt += 1
            time.sleep(backoff)
            backoff = min(MAX_BACKOFF, backoff * 2)
            continue
        except requests.exceptions.RequestException as e:
            logging.debug(f"RequestException {e} for {url} (attempt {attempt})")
            attempt += 1
            time.sleep(backoff)
            backoff = min(MAX_BACKOFF, backoff * 2)
            continue
        except Exception as e:
            logging.exception(f"Unexpected error during GET {url}: {e}")
            return {"status": None, "text": "", "error": str(e)}
    return {"status": None, "text": "", "error": f"max_retries_{max_retries}"}

# ----------------------
# Playwright JS check (desktop only)
# ----------------------
def playwright_check(url: str, tokens: List[str], timeout: int = 8) -> Dict:
    res = {"playwright": False, "console": [], "posts": [], "found_tokens": []}
    if not PLAYWRIGHT_AVAILABLE:
        res["error"] = "playwright_not_installed"
        return res
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            console_msgs = []
            def on_console(msg):
                try:
                    console_msgs.append(f"{msg.type}: {msg.text}")
                except Exception:
                    pass
            posts = []
            def on_request(req):
                try:
                    if req.method == "POST":
                        posts.append({"url": req.url, "post_data": req.post_data})
                except Exception:
                    pass
            page.on("console", on_console)
            page.on("request", on_request)
            page.goto(url, timeout=timeout*1000)
            time.sleep(1.0)
            browser.close()
            res.update({"playwright": True, "console": console_msgs, "posts": posts})
            for tkn in tokens:
                for c in console_msgs:
                    if tkn in c:
                        res["found_tokens"].append({"token": tkn, "via": "console", "msg": c})
                for p_ in posts:
                    if tkn in (p_.get("post_data") or "") or tkn in (p_.get("url") or ""):
                        res["found_tokens"].append({"token": tkn, "via": "post", "post": p_})
    except Exception as e:
        logging.exception(f"Playwright check error for {url}: {e}")
        res["error"] = str(e)
    return res

# ----------------------
# Terminal output helpers (compact, colored)
# ----------------------
def status_color_for_code(code: Optional[int]) -> str:
    if code is None:
        return "magenta"
    if 200 <= code < 300:
        return "light_blue"
    if 300 <= code < 400:
        return "cyan"
    if 400 <= code < 500:
        return "red"
    if 500 <= code < 600:
        return "magenta"
    return "white"

def print_result_brief(entry: Dict):
    # entry: target, injection_url, status, success (bool), reasons, snippet
    status = entry.get("status")
    code_text = str(status) if status is not None else "ERR"
    color = status_color_for_code(status)
    prefix = "[✓]" if entry.get("success") else "[.]"
    if entry.get("success"):
        prefix = color_text("[SUCCESS]", "green")
    msg = f"{prefix} {code_text} {entry.get('injection_url')}"

    # if success or notable reason, color and show reasons
    reasons = entry.get("reasons") or entry.get("confidence") or []
    reason_str = ""
    if entry.get("success") and entry.get("reasons"):
        reason_str = " | " + ",".join(entry.get("reasons"))
    print(color_text(msg + reason_str, color))

# ----------------------
# Core worker (thread-safe, dedup)
# ----------------------
class PerTargetControl:
    def __init__(self):
        self.lock = threading.Lock()
        self.last_request_time: Dict[str, float] = {}
        self.consecutive_block: Dict[str, int] = {}

    def wait_min_interval(self, target: str, min_interval: float):
        with self.lock:
            last = self.last_request_time.get(target, 0.0)
            now = time.time()
            sleep_for = max(0.0, min_interval - (now - last))
            if sleep_for > 0:
                logging.debug(f"Per-target wait {sleep_for:.2f}s for {target}")
                time.sleep(sleep_for)

    def record_request(self, target: str):
        with self.lock:
            self.last_request_time[target] = time.time()

    def inc_block(self, target: str):
        with self.lock:
            self.consecutive_block[target] = self.consecutive_block.get(target, 0) + 1

    def reset_block(self, target: str):
        with self.lock:
            self.consecutive_block[target] = 0

    def get_block(self, target: str) -> int:
        with self.lock:
            return self.consecutive_block.get(target, 0)

per_target_ctrl = PerTargetControl()

def worker_inject(target: str,
                  payload_template: str,
                  param_override: Optional[str],
                  session: requests.Session,
                  min_interval: float,
                  delay_base: float,
                  jitter: float,
                  timeout: int,
                  playwright_flag: bool,
                  oob_domain: Optional[str],
                  checked_set: Set[Tuple[str, str, str]]) -> List[Dict]:
    out: List[Dict] = []
    if SHUTDOWN:
        return out
    try:
        parsed = urlparse(target)
        candidate_params = discover_params(target)
        if param_override:
            candidate_params = [param_override] + [p for p in candidate_params if p != param_override]
        # Generate a run token and variants
        run_token = rand_token()
        variants = generate_variants_from_template(payload_template, token=run_token)
        # cookie template
        cookie_key = f"xinj_{random.randint(1000,9999)}"
        # Respect per-target min interval
        per_target_ctrl.wait_min_interval(target, min_interval)
        for p in candidate_params:
            if SHUTDOWN:
                break
            for v in variants:
                inj_key = (target, p, v["payload"])
                with lock:
                    if inj_key in checked_set:
                        logging.debug(f"Skipping duplicate inj {inj_key}")
                        continue
                    checked_set.add(inj_key)
                # build injection URL
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[p] = [v["payload"]]
                new_q = urlencode(qs, doseq=True)
                inj_url = urlunparse(parsed._replace(query=new_q))
                # polite pacing
                time.sleep(delay_base + random.random() * jitter)
                per_target_ctrl.wait_min_interval(target, min_interval)
                per_target_ctrl.record_request(target)
                # headers and cookies
                headers = {
                    "User-Agent": random.choice(USER_AGENT_POOL),
                    "Referer": target,
                    "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9"])
                }
                cookies = {cookie_key: run_token}
                # perform robust GET
                resp = robust_get(session, inj_url, headers=headers, cookies=cookies, timeout=timeout)
                status = resp.get("status")
                text = resp.get("text", "") or ""
                success = False
                reasons = []
                confidence = 0
                # reflection detection
                if run_token in text:
                    success = True
                    reasons.append("reflection_token")
                    confidence += 70
                # server error heuristic
                if status and status >= 500:
                    reasons.append("server_error")
                    confidence += 5
                # OOB reference note
                if oob_domain and oob_domain in v["payload"]:
                    reasons.append("oob_reference")
                # Optional Playwright verification (desktop only)
                pw_info = None
                if playwright_flag and PLAYWRIGHT_AVAILABLE and not success:
                    try:
                        pw_info = playwright_check(inj_url, [run_token], timeout=timeout)
                        if pw_info.get("found_tokens"):
                            success = True
                            reasons.append("playwright_exec")
                            confidence += 30
                    except Exception as e:
                        logging.debug(f"Playwright exception for {inj_url}: {e}")
                # adaptive backoff on 403/429
                if status in (403, 429):
                    per_target_ctrl.inc_block(target)
                    backoff = min(MAX_BACKOFF, 1 + per_target_ctrl.get_block(target) * 2)
                    logging.warning(f"Target {target} responded {status}. Backing off {backoff}s (polite).")
                    time.sleep(backoff)
                else:
                    per_target_ctrl.reset_block(target)
                entry = {
                    "target": target,
                    "injected_param": p,
                    "variant_type": v["type"],
                    "payload_preview": v["payload"][:500],
                    "injection_url": inj_url,
                    "status": status,
                    "success": success,
                    "confidence": confidence,
                    "reasons": reasons,
                    "snippet": text[:500]
                }
                if pw_info is not None:
                    entry["playwright"] = pw_info
                out.append(entry)
                # print brief colored result
                print_result_brief(entry)
                # if success for this param, break further variants for param
                if success:
                    break
            # if success occurred for param, skip other params
            if any(r["success"] for r in out if r.get("injected_param") == p):
                break
        return out
    except Exception as e:
        logging.exception(f"Worker injection unhandled exception for {target}: {e}")
        return [{"target": target, "error": str(e), "traceback": traceback.format_exc()}]

# ----------------------
# Orchestration + dedupe
# ----------------------
def orchestrate(targets: List[str],
                payload_templates: List[str],
                param: Optional[str],
                threads: int,
                min_interval: float,
                delay: float,
                jitter: float,
                timeout: int,
                playwright_flag: bool,
                oob_domain: Optional[str],
                only_success: bool,
                output_path: str,
                output_format: str) -> List[Dict]:
    session = requests.Session()
    session.headers.update({"User-Agent": random.choice(USER_AGENT_POOL)})
    results: List[Dict] = []
    checked_set: Set[Tuple[str, str, str]] = set()
    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = []
        for t in targets:
            for templ in payload_templates:
                if SHUTDOWN:
                    break
                futures.append(exe.submit(worker_inject, t, templ, param, session,
                                          min_interval, delay, jitter, timeout, playwright_flag, oob_domain, checked_set))
        for fut in as_completed(futures):
            try:
                res_list = fut.result()
                for entry in res_list:
                    if only_success and not entry.get("success"):
                        continue
                    with lock:
                        results.append(entry)
                if SHUTDOWN:
                    logging.info("Shutdown requested — halting orchestrator collection.")
                    break
            except Exception as e:
                logging.exception(f"Orchestrator: worker future exception: {e}")
    # Save final results
    try:
        if output_format == "csv":
            if not results:
                atomic_write(output_path, "")
            else:
                keys = sorted(set().union(*(r.keys() for r in results)))
                with open(output_path, "w", newline="", encoding="utf-8") as outf:
                    writer = csv.DictWriter(outf, fieldnames=keys)
                    writer.writeheader()
                    for r in results:
                        row = {k: (json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v) for k, v in r.items()}
                        writer.writerow(row)
        else:
            atomic_write(output_path, json.dumps(results, indent=2, ensure_ascii=False))
    except Exception:
        logging.exception("Failed to save final results; attempt fallback write.")
    return results

# ----------------------
# CLI / main
# ----------------------
def parse_args():
    p = argparse.ArgumentParser(
        prog="xinjection_final.py",
        description="xinjection_final — terminal/Termux-friendly, robust, legal payload injection tool. "
                    "Use only on targets you own or are authorized to test. "
                    "Default payloads are harmless and tokenized. "
                    "See --confirm requirement below.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    p.add_argument("-u", "--url", help="Single target URL (include scheme).")
    p.add_argument("-l", "--list", help="File path with newline-separated target URLs.")
    p.add_argument("-p", "--payload", help="Single payload template. Use {token} placeholder to insert unique token.")
    p.add_argument("--payload-list", help="File with payload templates, one per line.")
    p.add_argument("--generate", choices=["xss_harmless", "xss_basic", "sqli_test", "lfi_test", "random_tokens"],
                   help="Generate payload templates for quick runs.")
    p.add_argument("--gen-count", type=int, default=6, help="Count for generated payload templates.")
    p.add_argument("--param", help="Specific query parameter to target (optional).")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Concurrency workers.")
    p.add_argument("--min-interval", type=float, default=0.5,
                   help="Minimum seconds between requests to same target (per-target rate limit).")
    p.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Base delay between requests (seconds).")
    p.add_argument("--jitter", type=float, default=DEFAULT_JITTER, help="Max random jitter (seconds).")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP request timeout (seconds).")
    p.add_argument("--output", default="xinjection_results.json", help="Output file path (json or csv).")
    p.add_argument("--format", choices=["json", "csv"], default="json", help="Output format.")
    p.add_argument("--only-success", action="store_true", help="Save only successful entries.")
    p.add_argument("--oob-domain", help="Your OOB domain for blind XSS (only use if you control it).")
    p.add_argument("--playwright", action="store_true", help="Enable Playwright JS verification (desktop/VM only).")
    p.add_argument("--confirm", required=True, help="Type I_HAVE_AUTH to confirm you are authorized to test targets.")
    return p.parse_args()

def main():
    print(BANNER)
    args = parse_args()
    if args.confirm != "I_HAVE_AUTH":
        logging.error("REFUSING: pass --confirm I_HAVE_AUTH to acknowledge authorization.")
        sys.exit(1)
    targets: List[str] = []
    if args.url:
        targets.append(args.url.strip())
    if args.list:
        if not os.path.exists(args.list):
            logging.error("Targets file not found: %s", args.list)
            sys.exit(1)
        targets += load_lines(args.list)
    if not targets:
        logging.error("No targets provided (use -u or -l).")
        sys.exit(1)
    payload_templates: List[str] = []
    if args.payload:
        payload_templates.append(args.payload)
    if args.payload_list:
        if not os.path.exists(args.payload_list):
            logging.error("Payload list file not found: %s", args.payload_list)
            sys.exit(1)
        payload_templates += load_lines(args.payload_list)
    if args.generate:
        payload_templates += generate_payload_templates(args.generate, args.gen_count, args.oob_domain)
    # dedupe templates
    payload_templates = [p for i, p in enumerate(payload_templates) if p and p not in payload_templates[:i]]
    if not payload_templates:
        logging.error("No payloads supplied. Use -p, --payload-list, or --generate.")
        sys.exit(1)
    if args.playwright and not PLAYWRIGHT_AVAILABLE:
        logging.warning("Playwright not available in this environment; --playwright will be ignored.")
        args.playwright = False
    logging.info("Starting run: targets=%d payloads=%d threads=%d", len(targets), len(payload_templates), args.threads)
    start = time.time()
    results = orchestrate(
        targets=targets,
        payload_templates=payload_templates,
        param=args.param,
        threads=args.threads,
        min_interval=args.min_interval,
        delay=args.delay,
        jitter=args.jitter,
        timeout=args.timeout,
        playwright_flag=args.playwright,
        oob_domain=args.oob_domain,
        only_success=args.only_success,
        output_path=args.output,
        output_format=args.format
    )
    elapsed = time.time() - start
    logging.info("Run completed in %.1f seconds. Collected %d entries.", elapsed, len(results))
    try:
        # save final results already done in orchestrate; ensure file exists
        if not os.path.exists(args.output):
            atomic_write(args.output, json.dumps(results, indent=2, ensure_ascii=False))
    except Exception:
        logging.exception("Saving final results fallback failed.")
    succ = sum(1 for r in results if r.get("success"))
    logging.info("Summary: %d successful items detected.", succ)
    print(color_text(f"\n[DONE] Results saved to {args.output}. Successes: {succ}", "green"))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        logging.exception(f"Fatal error in main: {e}")
        print(color_text("Fatal error occurred. Check log file: " + LOG_FILE, "red"))
        sys.exit(1)
