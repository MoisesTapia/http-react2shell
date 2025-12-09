# React2Shell Nmap Detection Script (NSE)

Detection for CVE-2025-55182 / CVE-2025-66478 – React Server Components / Next.js

This repository contains a Nmap Scripting Engine (NSE) script written in Lua designed to safely detect the critical vulnerability known as React2Shell, affecting React Server Components (RSC) and React Server Actions (RSA) implementations—including many Next.js deployments.

The detection method uses a non-intrusive side-channel technique based on server-side error behavior when handling malformed React Flight payloads.
No exploitation, no code execution, and no unsafe operations are performed.

## About the Vulnerability

React2Shell (CVE-2025-55182 / CVE-2025-66478) is a critical design flaw in React Server Components pipelines that can allow:

Unauthorized access to internal component references

Arbitrary property access

Potential Remote Code Execution (RCE) under specific frameworks

Server-side data leakage and execution flow manipulation

The vulnerability is triggered when React attempts to resolve crafted React Flight references such as:

```bash
["$1:aa:aa"]
```

On vulnerable servers, this produces a 500 error containing the characteristic pattern:

```bash
E{"digest":"..."}
```

This script detects that pattern without attempting any harmful operations.

## Features

✔ Safe & passive detection (no exploitation, no RCE attempts)

✔ Detects the high-fidelity React Flight crash signature

✔ Works on HTTP & HTTPS

✔ User-configurable paths and timeouts

✔ Automatically avoids false positives from Vercel/Netlify mitigations

✔ Output compatible with automated pipelines and SIEM ingestion

✔ Lightweight and suitable for red teaming, bug bounty, incident response & CI/CD scanning


## Download & Installation

### 1 Clone this repository

```bash
git clone https://github.com/MoisesTapia/http-react2shell.git
cd http-react2shell
```


## Script Location

Place the file inside your Nmap scripts directory:

```bash
sudo cp http-react2shell.nse /usr/share/nmap/scripts/
```

Update the script index:

```bash
sudo nmap --script-updatedb
```

## Usage Examples

### Basic HTTP Scan

```bash
nmap -p80 --script http-react2shell <host>
```

### HTTPS Scan (common for Next.js)

```bash
nmap -p443 --script http-react2shell \
  --script-args 'react2shell.path=/'
  <host>
```

### Scan Server Actions endpoint

```bash
nmap -p443 --script http-react2shell \
  --script-args 'react2shell.path=/api/action'
  <host>
```

### Custom Timeout

```bash
nmap -p443 --script http-react2shell \
  --script-args 'react2shell.path=/,react2shell.timeout=20000'
  <host>
```
### Scan multiple targets

```bash
nmap -iL targets.txt -p80,443 \
  --script http-react2shell
```

### Include additional useful NSE scripts

```bash
nmap -sV -p80,443 \
  --script "http-react2shell,http-headers,http-server-header,http-security-headers" \
  <host>
```

---

## Output Example

```bash

PORT   STATE SERVICE
443/tcp open  https
| http-react2shell:
|   VULNERABLE: possible React2Shell (CVE-2025-55182 / CVE-2025-66478)
|     Path: /
|     Evidence: HTTP 500 + E{"digest" found in response
|_    Notes: high-fidelity side-channel; verify manually and patch immediately.
```

## References

https://react2shell.com/

https://github.com/lachlan2k/React2Shell-CVE-2025-55182-original-poc

https://github.com/sammwyy/R2SAE

Technical analysis articles & research papers on React Flight internals

## ⚠️ Legal Disclaimer

This project is provided for educational, research, and defensive security purposes only.
Do not scan systems you do not own or lack explicit permission to test.
The maintainers are not responsible for misuse or any resulting damage.

## ❤️ Contributing

Pull requests, improvements, and additional detection heuristics are welcome.
You may contribute:

Multi-path scanning support

WAF evasion modes

Additional fingerprinting

Integration with Nmap's built-in vulns framework

## ⭐ Support the Project

If this tool helps you in red teaming, bug bounty, or defensive security,
consider giving the repository a star ⭐ on GitHub!
