Key Features

🎨 Color-coded output → instantly see 200 (blue), 404 (red), 500 (magenta), success highlights (green).

⚡ Multi-threaded engine → test URLs quickly with adaptive throttling and retry logic.

🧱 Firewall-friendly & legal evasion → randomized headers, jitter, and backoff to avoid noisy scans.

🕵 Payload generation & mutation → supports single payloads, payload lists, and layered encodings.

🌐 Blind injection support (OOB) → append unique callback tokens for external monitoring.

🖥 JS/DOM detection (Playwright optional) → verify if payloads execute in a browser context.

🔒 Bedrock error handling → unbreakable, catches all network, file, and threading errors.

📜 Clean results export → JSON/CSV output with URLs, status codes, snippets, and injection findings.


Usage Examples

Test a single URL with a harmless payload:

python3 main.py.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --generate xss_harmless --threads 10 --output results.json --confirm I_HAVE_AUTH

Test multiple URLs from a file with your own payload list:

python3 xinjection_final.py -l urls.txt -pl payloads.txt --threads 20 --output results.csv --confirm I_HAVE_AUTH

Enable blind injection tracking:

python3 xinjection_final.py -u "http://target.com/page?id=1"

# Payload-needle
this tool injects payloads
