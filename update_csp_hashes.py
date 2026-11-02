#!/usr/bin/env python3
"""Recompute the sha256 hashes of every inline script in the page's
Content-Security-Policy meta tag.

Usage: python3 update_csp_hashes.py index.html

Run after ANY edit inside a <script> tag. Skips HTML comments, scripts
with a src attribute, and data blocks (JSON, JSON-LD, settings), which
the browser never runs. Safe to run repeatedly; Netlify can run it as
the build command.
"""
import base64, hashlib, re, sys

DATA_TYPES = ("application/json", "application/ld+json", "text/plain", "text/template")

def main(path):
    with open(path, encoding="utf-8", newline="") as f:
        html = f.read()
    scan = re.sub(r"<!--.*?-->", lambda m: " " * len(m.group(0)), html, flags=re.S)
    hashes = []
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script\s*>", scan, flags=re.S | re.I):
        attrs = m.group(1)
        if re.search(r"\bsrc\s*=", attrs, re.I):
            continue
        t = re.search(r"\btype\s*=\s*[\"']([^\"']+)", attrs, re.I)
        if t and t.group(1).strip().lower() in DATA_TYPES:
            continue
        body = html[m.start(2):m.end(2)]
        h = "'sha256-" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode() + "'"
        if h not in hashes:
            hashes.append(h)
    meta = re.search(r'(<meta[^>]+http-equiv="Content-Security-Policy"[^>]+content=")([^"]*)(")', html, re.I)
    if not meta:
        sys.exit("No Content-Security-Policy meta tag found in " + path)
    policy = meta.group(2)
    new_src = "script-src " + " ".join(hashes)
    if re.search(r"script-src(?!-)[^;]*", policy):
        policy = re.sub(r"script-src(?!-)[^;]*", new_src, policy, count=1)
    else:
        policy = new_src + "; " + policy
    out = html[:meta.start(2)] + policy + html[meta.end(2):]
    changed = out != html
    if changed:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(out)
    print(("Updated" if changed else "Already correct:") + f" {len(hashes)} script hash(es) in {path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 update_csp_hashes.py <file.html>")
    main(sys.argv[1])
