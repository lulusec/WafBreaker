<img width="1891" height="831" alt="image" src="https://github.com/user-attachments/assets/fbd3861a-b23f-4516-b700-28ba8c550346" />



---

## What is WafBreaker?

WafBreaker is a **Burp Suite extension** written in Jython 2.7. It attaches to any HTTP request via the right-click context menu and runs a fully automated, multi-phase scan designed to:

- **Detect and fingerprint** the WAF in front of the target
- **Bypass it** using 23 bypass technique sections (IP spoofing, charset confusion, encoding tricks, protocol downgrade, multipart body, double URL encoding, null bytes, and more)
- **Confirm real vulnerabilities** — SQLi (boolean, time, error, union, stacked), LFI (depth-ordered, 60+ path transforms, Linux + Windows targets), XSS, SSTI, XXE, SSRF, and others
- **Report findings** directly inside Burp's Scanner tab as proper issues with severity, confidence, payloads, and extracted proof

---

## Files in this folder

| File | Purpose |
|---|---|
| `waf_clean.py` | **Load this into Burp.** AV-clean build of the extension. |
| `waf_source_backup.py` | Full annotated source. Edit this, then run `build.py` to rebuild. |
| `build.py` | Strips comments/blanks from the source and writes `waf_clean.py`. |


---

## Why `waf_clean.py` and not `waf_source_backup.py`?

**Windows Defender and most endpoint AV solutions flag the raw source file.**

The source (`waf_source_backup.py`) contains plaintext strings that match AV signatures — things like `' OR 1=1--`, `../../../etc/passwd`, `X-Forwarded-For: 127.0.0.1`, and the hundreds of payload strings packed into the payload lists. Defender sees those pattern clusters and quarantines the file before Burp can even load it.

`waf_clean.py` is the same code run through `build.py`, which:
- Strips all comments and docstrings
- Collapses blank lines
- Produces a compact single-file output that is functionally identical but without the readable annotation layer that AV heuristics pattern-match against

**Always load `waf_clean.py` into Burp. Always edit `waf_source_backup.py` and rebuild.**


## How to use

1. Open **Burp Suite** → **Extensions** → **Add**
2. Set type to **Python**, select `waf_clean.py`, click **Next**
3. No errors in the Output tab → extension loaded
4. Navigate to any request in Proxy / Repeater / Target
5. **Right-click** → **Extensions** → **WafBreaker** → choose scan type:
   - `SQL Injection`
   - `XSS`
   - `LFI` ← local file inclusion depth scan
   - `SSTI`, `XXE`, `SSRF`, `Open Redirect`, `NoSQL`, etc.
6. Results appear in **Target → Issues** and the **Extensions output tab**

The scan runs in a background thread — Burp stays responsive.

---



*WafBreaker — built session by session.*
