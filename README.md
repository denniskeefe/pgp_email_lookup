# pgp_email_lookup

A lightweight OSINT command-line tool for discovering verified email addresses via the [keys.openpgp.org](https://keys.openpgp.org) keyserver.

When a person uploads a PGP key to this keyserver and verifies their email address, that association becomes publicly searchable. This tool queries the keyserver by name or email address and extracts any verified identity information attached to matching keys.

---

## Why this is useful

Unlike most email lookup methods, addresses returned by this keyserver are **verified** — the owner clicked a confirmation link. A result here is strong signal that the address is real and in active use. Subjects who have keys published tend to be developers, security researchers, open source contributors, journalists, and privacy-conscious professionals.

This tool is most effective as a **corroboration layer** in a broader workflow:

- Find a PGP fingerprint on a subject's GitHub profile, personal site, or forum signature
- Search that fingerprint (or their name/suspected email) here to surface the verified address
- Feed confirmed addresses into breach checkers, domain recon, or other OSINT pipelines

---

## Requirements

- Python 3.9+
- `requests` (required)
- `pgpy` (optional — enables full key parsing including creation date, expiry, and revocation status; falls back to regex extraction if not installed)

```bash
pip install requests pgpy
```

---

## Installation

```bash
git clone https://github.com/yourusername/pgp_email_lookup.git
cd pgp_email_lookup
pip install requests pgpy
```

No virtual environment required for basic use.

---

## Usage

### Search by name

```bash
python3 pgp_email_lookup.py "Jane Smith"
```

### Search by email address

```bash
python3 pgp_email_lookup.py "jane@protonmail.com"
```

### Multiple queries in one run

```bash
python3 pgp_email_lookup.py "jane@protonmail.com" "john@example.com" "Bob Smith"
```

Names and email addresses can be mixed freely in the same command.

---

## Flags

| Flag | Description |
|------|-------------|
| `--output FILE` | Save results to a plain text file |
| `--json` | Output results as JSON (pipe-friendly) |
| `--raw` | Print the full raw PGP key block(s) |
| `--no-color` | Disable ANSI color output (useful for logging) |

### Examples

```bash
# Save results to a file
python3 pgp_email_lookup.py "Jane Smith" --output results.txt

# JSON output — good for piping into other tools
python3 pgp_email_lookup.py "jane@protonmail.com" --json

# Multiple targets, save to file
python3 pgp_email_lookup.py "jane@protonmail.com" "john@example.com" --output results.txt

# No color for clean log output
python3 pgp_email_lookup.py "Jane Smith" --no-color
```

---

## Sample output

```
OpenPGP Keyserver — Email Discovery
keys.openpgp.org  |  VKS API v1
--------------------------------------------
Searching: jane@protonmail.com

Query: jane@protonmail.com
Keys found: 1

Key 1  A1B2C3D4E5F6...  [active]
  Created: 2021-03-14   Expires: no expiry
  User IDs:
    + Jane Smith <jane@protonmail.com>
      email: jane@protonmail.com  (verified)

--------------------------------------------
Confirmed email addresses (1):
  jane@protonmail.com
```

---

## API routing

The tool automatically selects the correct keyserver endpoint based on input type:

- **Email address** → `/vks/v1/by-email/` (exact lookup)
- **Name or other query** → `/vks/v1/search` (full-text search)

No configuration needed.

---

## Limitations

- Only returns results for subjects who have uploaded a PGP key **and** verified their email with the keyserver
- Coverage skews toward technical users — most subjects will return no results
- The keyserver does not support bulk enumeration or wildcard queries
- Name searches require sufficient specificity — very short or common queries may return a 400 error; use a full name or add context

---

## Legal and ethical use

This tool queries a public keyserver API using only data that key owners have voluntarily published and verified. Always ensure your use of OSINT tools complies with applicable laws and regulations, including the FCRA, DPPA, and Florida Chapter 493 where applicable.

---

## Dependencies

- [requests](https://pypi.org/project/requests/)
- [pgpy](https://pypi.org/project/pgpy/) (optional)

---

## License

MIT
