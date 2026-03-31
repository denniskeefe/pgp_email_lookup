#!/usr/bin/env python3
"""
pgp_email_lookup.py — OpenPGP keyserver email discovery tool
Queries keys.openpgp.org by email address, fingerprint, or key ID.

Usage:
    python3 pgp_email_lookup.py "jane@protonmail.com"
    python3 pgp_email_lookup.py "jane@protonmail.com" --raw
    python3 pgp_email_lookup.py "jane@protonmail.com" --output results.txt
    python3 pgp_email_lookup.py "jane@protonmail.com" --json

Requirements:
    pip install requests pgpy --break-system-packages
"""

import sys
import re
import json
import argparse
import textwrap
from datetime import datetime
from typing import Optional, List, Dict

try:
    import requests
except ImportError:
    sys.exit("[!] Missing dependency: pip install requests --break-system-packages")

try:
    import pgpy
    HAS_PGPY = True
except ImportError:
    HAS_PGPY = False

KEYSERVER = "https://keys.openpgp.org"
VKS_SEARCH = f"{KEYSERVER}/vks/v1/search"
VKS_LOOKUP  = f"{KEYSERVER}/vks/v1/by-fingerprint"

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RED    = "\033[31m"
GRAY   = "\033[90m"


def no_color():
    global RESET, BOLD, DIM, GREEN, YELLOW, CYAN, RED, GRAY
    RESET = BOLD = DIM = GREEN = YELLOW = CYAN = RED = GRAY = ""


def banner():
    print(f"{BOLD}OpenPGP Keyserver — Email Discovery{RESET}")
    print(f"{GRAY}keys.openpgp.org  |  VKS API v1{RESET}")
    print(f"{GRAY}{'-' * 44}{RESET}")


def classify_query(query: str) -> str:
    """Return 'email', 'fingerprint', 'keyid', or 'unknown'."""
    q = query.strip()
    if re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", q):
        return "email"
    clean = re.sub(r"^0x", "", q, flags=re.IGNORECASE)
    if re.match(r"^[0-9A-Fa-f]{40}$", clean):
        return "fingerprint"
    if re.match(r"^[0-9A-Fa-f]{16}$", clean):
        return "keyid"
    return "unknown"


def search_keyserver(query: str) -> Optional[str]:
    """Fetch raw armored PGP key block from the keyserver.
    Supports: email address, 40-char fingerprint, 16-char key ID.
    """
    from urllib.parse import quote
    q = query.strip()
    qtype = classify_query(q)

    if qtype == "email":
        url = f"{KEYSERVER}/vks/v1/by-email/{quote(q, safe='')}"
    elif qtype == "fingerprint":
        fp = re.sub(r"^0x", "", q, flags=re.IGNORECASE).upper()
        url = f"{KEYSERVER}/vks/v1/by-fingerprint/{fp}"
    elif qtype == "keyid":
        kid = re.sub(r"^0x", "", q, flags=re.IGNORECASE).upper()
        url = f"{KEYSERVER}/vks/v1/by-keyid/{kid}"
    else:
        sys.exit(f"{RED}[!] Unsupported query: {q!r}\n    Accepted: email address, 40-char fingerprint, or 16-char key ID{RESET}")

    params = {}

    try:
        r = requests.get(
            url,
            params=params,
            timeout=15,
            headers={"User-Agent": "pgp-email-lookup/1.0"}
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.text
    except requests.exceptions.ConnectionError:
        sys.exit(f"{RED}[!] Connection failed. Check your internet connection.{RESET}")
    except requests.exceptions.Timeout:
        sys.exit(f"{RED}[!] Request timed out.{RESET}")
    except requests.exceptions.HTTPError as e:
        sys.exit(f"{RED}[!] HTTP error: {e}{RESET}")


def split_key_blocks(armored: str) -> List[str]:
    """Split concatenated PGP blocks into individual blocks."""
    marker = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    parts = armored.split(marker)
    blocks = []
    for part in parts[1:]:
        block = marker + part
        end = block.find("-----END PGP PUBLIC KEY BLOCK-----")
        if end != -1:
            blocks.append(block[:end + len("-----END PGP PUBLIC KEY BLOCK-----")])
    return blocks


def parse_block_pgpy(armored: str) -> dict:
    """Parse a PGP key block using pgpy for accurate UID extraction."""
    result = {"uids": [], "fingerprint": None, "created": None, "expires": None, "revoked": False}
    try:
        key, _ = pgpy.PGPKey.from_blob(armored)
        result["fingerprint"] = str(key.fingerprint)
        result["created"] = key.created.strftime("%Y-%m-%d") if key.created else None
        result["expires"] = key.expires_at.strftime("%Y-%m-%d") if key.expires_at else None
        result["revoked"] = key.is_revoked

        for uid in key.userids:
            uid_str = str(uid)
            email = extract_email(uid_str)
            result["uids"].append({
                "raw": uid_str,
                "email": email,
                "verified": email is not None,
            })
    except Exception as e:
        result["parse_error"] = str(e)
    return result


def parse_block_regex(armored: str) -> dict:
    """Fallback parser using regex when pgpy is unavailable."""
    result = {"uids": [], "fingerprint": None, "created": None, "expires": None, "revoked": False}

    # Extract fingerprint hint from Comment line if present
    fp_match = re.search(r"Comment:\s*([0-9A-Fa-f]{40})", armored)
    if fp_match:
        result["fingerprint"] = fp_match.group(1).upper()

    # Extract emails from the raw armored text (will catch any that appear in headers)
    email_re = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    emails_found = list(dict.fromkeys(email_re.findall(armored)))

    for email in emails_found:
        result["uids"].append({
            "raw": email,
            "email": email,
            "verified": True,
        })

    # If no emails found in headers, note unverified
    if not result["uids"]:
        result["uids"].append({
            "raw": "(no verified identity information)",
            "email": None,
            "verified": False,
        })

    return result


def extract_email(uid_str: str) -> Optional[str]:
    """Extract email address from a UID string like 'Name <email@domain.com>'."""
    m = re.search(r"<([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>", uid_str)
    if m:
        return m.group(1)
    m2 = re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", uid_str)
    if m2:
        return m2.group(0)
    return None


def parse_keys(armored: str) -> List[dict]:
    """Parse all key blocks from a keyserver response."""
    blocks = split_key_blocks(armored)
    results = []
    for block in blocks:
        if HAS_PGPY:
            parsed = parse_block_pgpy(block)
        else:
            parsed = parse_block_regex(block)
        parsed["raw_block"] = block
        results.append(parsed)
    return results


def print_results(query: str, keys: List[dict]):
    """Print formatted results to stdout."""
    print(f"\n{BOLD}Query:{RESET} {query}")
    print(f"{BOLD}Keys found:{RESET} {len(keys)}\n")

    all_emails = []

    for i, key in enumerate(keys, 1):
        fp = key.get("fingerprint") or "unknown fingerprint"
        created = key.get("created") or "unknown"
        expires = key.get("expires") or "no expiry"
        revoked = key.get("revoked", False)

        status_label = f"{RED}[REVOKED]{RESET}" if revoked else f"{GREEN}[active]{RESET}"
        print(f"{BOLD}Key {i}{RESET}  {GRAY}{fp}{RESET}  {status_label}")
        print(f"  {DIM}Created: {created}   Expires: {expires}{RESET}")

        uids = key.get("uids", [])
        if uids:
            print(f"  {CYAN}User IDs:{RESET}")
            for uid in uids:
                raw = uid.get("raw", "")
                email = uid.get("email")
                verified = uid.get("verified", False)

                if verified and email:
                    print(f"    {GREEN}+{RESET} {raw}")
                    print(f"      {GRAY}email:{RESET} {BOLD}{email}{RESET}  {GREEN}(verified){RESET}")
                    all_emails.append(email)
                else:
                    print(f"    {YELLOW}-{RESET} {raw}  {YELLOW}(no verified email){RESET}")
        else:
            print(f"  {YELLOW}No user ID information available{RESET}")

        print()

    if all_emails:
        print(f"{GRAY}{'-' * 44}{RESET}")
        print(f"{BOLD}Confirmed email addresses ({len(all_emails)}):{RESET}")
        for email in all_emails:
            print(f"  {GREEN}{email}{RESET}")
        print()

    if not HAS_PGPY:
        print(f"{YELLOW}[note] pgpy not installed — using regex fallback. Install pgpy for full UID parsing.{RESET}")
        print(f"{YELLOW}       pip install pgpy --break-system-packages{RESET}\n")


def build_json_output(query: str, keys: List[dict]) -> dict:
    """Build a JSON-serializable result dict."""
    all_emails = []
    key_summaries = []

    for key in keys:
        uids = key.get("uids", [])
        emails = [u["email"] for u in uids if u.get("email")]
        all_emails.extend(emails)
        key_summaries.append({
            "fingerprint": key.get("fingerprint"),
            "created": key.get("created"),
            "expires": key.get("expires"),
            "revoked": key.get("revoked", False),
            "uids": uids,
            "emails": emails,
        })

    return {
        "query": query,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "keys_found": len(keys),
        "emails_found": list(dict.fromkeys(all_emails)),
        "keys": key_summaries,
    }


def save_output(path: str, query: str, keys: List[dict]):
    """Write plain-text results to a file."""
    all_emails = []
    lines = []
    lines.append(f"OpenPGP Keyserver — Email Discovery")
    lines.append(f"Query: {query}")
    lines.append(f"Timestamp: {datetime.utcnow().isoformat()}Z")
    lines.append(f"Keys found: {len(keys)}")
    lines.append("-" * 50)

    for i, key in enumerate(keys, 1):
        fp = key.get("fingerprint") or "unknown"
        lines.append(f"\nKey {i} | Fingerprint: {fp}")
        lines.append(f"  Created: {key.get('created') or 'unknown'}  |  Expires: {key.get('expires') or 'none'}  |  Revoked: {key.get('revoked', False)}")
        for uid in key.get("uids", []):
            raw = uid.get("raw", "")
            email = uid.get("email")
            verified = uid.get("verified", False)
            status = "verified" if verified else "unverified"
            lines.append(f"  UID: {raw}  [{status}]")
            if email:
                all_emails.append(email)
                lines.append(f"  Email: {email}")

    lines.append("\n" + "-" * 50)
    lines.append(f"Confirmed emails ({len(all_emails)}):")
    for email in all_emails:
        lines.append(f"  {email}")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"{GREEN}[+] Results saved to:{RESET} {path}")


def main():
    parser = argparse.ArgumentParser(
        description="Search keys.openpgp.org by name to discover verified email addresses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        examples:
          python3 pgp_email_lookup.py "jane@protonmail.com"
          python3 pgp_email_lookup.py "jane@protonmail.com" --output results.txt
          python3 pgp_email_lookup.py "jane@protonmail.com" --json
          python3 pgp_email_lookup.py "jane@protonmail.com" --raw
          python3 pgp_email_lookup.py "jane@protonmail.com" --no-color
        """)
    )
    parser.add_argument("query", nargs="+", help="One or more email addresses, fingerprints (40 hex), or key IDs (16 hex)")
    parser.add_argument("--raw", action="store_true", help="Print raw PGP key blocks")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--output", metavar="FILE", help="Save results to a text file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        no_color()

    if not args.json:
        banner()

    all_json_results = []

    for query in args.query:
        query = query.strip()
        if not query:
            continue

        if not args.json:
            print(f"{GRAY}Searching: {query}{RESET}")

        armored = search_keyserver(query)

        if armored is None:
            if args.json:
                all_json_results.append({"query": query, "keys_found": 0, "emails_found": [], "keys": []})
            else:
                print(f"{YELLOW}[~] No keys found for:{RESET} {query}\n")
            continue

        keys = parse_keys(armored)

        if args.json:
            all_json_results.append(build_json_output(query, keys))
            continue

        print_results(query, keys)

        if args.raw:
            print(f"{GRAY}{'-' * 44}{RESET}")
            print(f"{BOLD}Raw key blocks:{RESET}\n")
            for key in keys:
                print(key.get("raw_block", ""))
                print()

    if args.json:
        output = all_json_results[0] if len(all_json_results) == 1 else all_json_results
        print(json.dumps(output, indent=2))
        sys.exit(0)

    if args.output:
        # Re-run queries to collect keys for file output
        all_keys_for_file = []
        for query in args.query:
            armored = search_keyserver(query.strip())
            if armored:
                all_keys_for_file.extend(parse_keys(armored))
        save_output(args.output, ", ".join(args.query), all_keys_for_file)


if __name__ == "__main__":
    main()
