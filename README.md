```
██╗    ██╗ █████╗ ███████╗██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗███████╗██████╗
██║    ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
██║ █╗ ██║███████║█████╗  ██████╔╝██████╔╝█████╗  ███████║█████╔╝ █████╗  ██████╔╝
██║███╗██║██╔══██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗
╚███╔███╔╝██║  ██║██║     ██████╔╝██║  ██║███████╗██║  ██║██║  ██╗███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

                    Burp Suite WAF Bypass & Vulnerability Scanner
                          Jython 2.7  ·  Windows 11  ·  Active Scan
```

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
| `eni.txt` | Notes file. Keep. |
| `lfi/` | LFI wordlists used during the matrix scan phase. |
| `sqli/` | SQLi payload lists (error, union, time-based) loaded at runtime. |

---

## Why `waf_clean.py` and not `waf_source_backup.py`?

**Windows Defender and most endpoint AV solutions flag the raw source file.**

The source (`waf_source_backup.py`) contains plaintext strings that match AV signatures — things like `' OR 1=1--`, `../../../etc/passwd`, `X-Forwarded-For: 127.0.0.1`, and the hundreds of payload strings packed into the payload lists. Defender sees those pattern clusters and quarantines the file before Burp can even load it.

`waf_clean.py` is the same code run through `build.py`, which:
- Strips all comments and docstrings
- Collapses blank lines
- Produces a compact single-file output that is functionally identical but without the readable annotation layer that AV heuristics pattern-match against

**Always load `waf_clean.py` into Burp. Always edit `waf_source_backup.py` and rebuild.**

To rebuild after edits:
```
cd C:\Users\hacke\Desktop\WAFko
python build.py
```

---

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

## Scan phase overview

```
Phase 0   WAF pre-probe          10 fast bypass techniques on a canary payload.
                                 If something works here, Phase 1 uses it immediately.

Phase 1   Initial probe          Sends the real detection payload.
                                 Uses Phase 0 bypass if found.

Phase 2   Full bypass sweep      23 sections (2-A → 2-W):
                                 IP headers, charset tricks, method override,
                                 junk params, compression, JSON wrapping,
                                 multipart body, HTTP/1.0 downgrade,
                                 param suffix, double URL encode, null byte, etc.

Phase S   SQLi systematic        Type detection (boolean/time/error/union/stacked)
                                 followed by targeted confirmation per type.

Phase S-LFI  LFI systematic      Depth-ordered scan: ../etc/passwd first,
                                 then ../../etc/passwd, ../../../etc/passwd, …
                                 Tries all 60+ path transforms at each depth.
                                 Once working depth found → scans all target files.

Phase 3   Payload sweep          Full payload list for the selected vuln type.

Phase 3.9 LFI matrix             Full cross-product: all depths × all files
                                 × all transforms. Fallback for edge cases.

Phase 3.8 Tamper combos          2- and 3-tamper chained combinations.
```

---

## LFI target files

**Linux:** `etc/passwd`, `etc/shadow`, `etc/hosts`, `proc/self/environ`,
`proc/version`, `var/log/apache2/access.log`, `var/log/nginx/access.log`,
`var/log/auth.log`, `root/.ssh/id_rsa`, `root/.ssh/authorized_keys`,
`var/www/html/wp-config.php`, k8s serviceaccount token, and more.

**Windows:** `windows\win.ini`, `windows\system32\drivers\etc\hosts`,
`boot.ini`, `windows\system32\config\sam`, `inetpub\wwwroot\web.config`,
IIS `applicationHost.config`, `panther\unattend\unattended.xml`, `php.ini`.

**Absolute paths:** `/etc/passwd`, `/etc/shadow`, `/root/.ssh/id_rsa`,
`C:\windows\win.ini`, `C:\inetpub\wwwroot\web.config`,
`C:\windows\system32\config\SAM`, k8s token at full runtime path.

**Detection patterns (28 total):** root entry, passwd shell fields,
win.ini sections (`[fonts]`, `[extensions]`, `[sounds]`, `[MCI extensions]`),
SSH private key header, AWS credentials, JWT token structure,
shadow hash format, WordPress config vars, web.config XML nodes,
HTTP access log lines, Windows system path leaks, base64 blobs (PHP wrappers).

---

## Editing & rebuilding

```
# Edit source
notepad waf_source_backup.py

# Syntax check before building
python -c "import ast; ast.parse(open('waf_source_backup.py').read()); print('OK')"

# Rebuild clean output
python build.py

# Reload in Burp: Extensions tab → select WafBreaker → Reload
```

---

*WafBreaker — built session by session.*
