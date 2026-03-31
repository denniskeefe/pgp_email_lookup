# pgp_email_lookup

A lightweight OSINT command-line tool for discovering verified email addresses via the [keys.openpgp.org](https://keys.openpgp.org) keyserver.

When a person uploads a PGP key and verifies their email address with the keyserver, that association becomes publicly queryable. This tool queries the keyserver by email address, fingerprint, or key ID and extracts any verified identity information attached to the matching key.

---

## Why this is useful

Unlike most email lookup methods, addresses returned by this keyserver are **verified** — the owner clicked a confirmation link to confirm ownership. A result here is strong signal that the address is real and in active use. Subjects who have keys published tend to be developers, security researchers, open source contributors, journalists, and privacy-conscious professionals.

This tool is most effective as a **corroboration layer** in a broader workflow:

- Find a PGP fingerprint or key ID on a subject's GitHub profile, personal site, or forum signature
- Query it here to retrieve the verified email address attached to that key
- Feed confirmed addresses into breach checkers, domain recon, or other OSINT pipelines

Alternatively, if you have a suspected email address, query it directly to confirm it is real and associated with a PGP key.

---

## Accepted query types

The keyserver VKS API does not support name search. The following query types are accepted:

| Type | Format | Example |
|------|--------|---------|
| Email address | `user@domain.tld` | `jane@protonmail.com` |
| PGP fingerprint | 40 hex characters | `8E8C33FA4626337976D97978069C0C348DD82C19` |
| Key ID | 16 hex characters | `069C0C348DD82C19` |

The `0x` prefix is accepted and stripped automatically for fingerprints and key IDs.

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

### Lookup by email address

```bash
python3 pgp_email_lookup.py "jane@protonmail.com"
```

### Lookup by fingerprint

```bash
python3 pgp_email_lookup.py "8E8C33FA4626337976D97978069C0C348DD82C19"
```

### Lookup by key ID

```bash
python3 pgp_email_lookup.py "069C0C348DD82C19"
```

### Multiple targets in one run

```bash
python3 pgp_email_lookup.py "jane@protonmail.com" "john@example.com" "8E8C33FA4626337976D97978069C0C348DD82C19"
```

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
python3 pgp_email_lookup.py "jane@protonmail.com" --output results.txt

# JSON output — good for piping into other tools
python3 pgp_email_lookup.py "jane@protonmail.com" --json

# Multiple targets, save to file
python3 pgp_email_lookup.py "jane@protonmail.com" "john@example.com" --output results.txt

# No color for clean log output
python3 pgp_email_lookup.py "jane@protonmail.com" --no-color

# Show raw PGP key block in output
python3 pgp_email_lookup.py "8E8C33FA4626337976D97978069C0C348DD82C19" --raw
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

Key 1  A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2  [active]
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

| Query type | Endpoint |
|------------|----------|
| Email address | `/vks/v1/by-email/<address>` |
| Fingerprint | `/vks/v1/by-fingerprint/<FINGERPRINT>` |
| Key ID | `/vks/v1/by-keyid/<KEY-ID>` |

No configuration needed. Unsupported input types return an error immediately without hitting the server.

---

## Limitations

- Only returns results for subjects who have uploaded a PGP key **and** verified their email with the keyserver
- Email lookups are exact match only — partial addresses are not accepted
- Coverage skews toward technical users — most subjects will return no results
- The keyserver does not support name search, wildcard queries, or bulk enumeration
- Email lookups are rate limited to one request per minute by the keyserver; fingerprint and key ID lookups are limited to five per second

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
