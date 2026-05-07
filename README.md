# ipf-fw-checker

A small Python script that uses the IP Fabric SDK to verify that **every device of type `fw`** in the inventory has at least one rule in either:

- **Technology > Security > ACL** (`/tables/security/acl`), or
- **Technology > Security > Zone Firewall — Policies** (`/tables/security/zone-firewall/policies`)

Devices with zero rules in both tables are reported as **NOK** — useful to spot firewalls where rule collection failed, the device was misclassified, or the security configuration genuinely is empty.

## How to install

### Match the SDK to your IP Fabric version

The `ipfabric` SDK is versioned to track IP Fabric itself — pick a release whose major and minor match your server (e.g. IP Fabric **7.10** → `ipfabric~=7.10.0`, IP Fabric **6.10** → `ipfabric~=6.10.0`). The `~=` "compatible release" operator means "any patch within this minor", so `~=7.10.0` allows `7.10.0`, `7.10.1`, … but not `7.11.0`. Available versions are listed on [PyPI](https://pypi.org/project/ipfabric/#history).

By default the script and `requirements.txt` install the latest available `ipfabric`. To pin to the minor matching your server, change `ipfabric` in **both** places below to e.g. `ipfabric~=7.10.0`:

- in `fw_checker.py`, inside the `# /// script` PEP 723 block at the top
- in `requirements.txt`

For example:

```python
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "ipfabric~=7.10.0",
#     "python-dotenv",
#     "rich",
# ]
# ///
```

### Run the install

You can run the script in two ways.

#### Option 1 — with [`uv`](https://docs.astral.sh/uv/) (recommended, no venv setup)

The script ships with a [PEP 723](https://peps.python.org/pep-0723/) inline metadata block listing its dependencies, so `uv` will create an ephemeral environment for you on first run:

```sh
uv run fw_checker.py
```

#### Option 2 — with `pip` and a regular virtualenv

```sh
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python fw_checker.py
```

## How to use

### Environment file

Copy the `.env.example` file:

```sh
cp .env.example .env
```

Then edit `.env`:

- `IPF_URL` — URL of your IP Fabric server, e.g. `https://ipfabric.example.com`
- `IPF_TOKEN` — API token
- `IPF_SNAPSHOT` — `$last` (default), `$prev`, `$lastLocked`, or a snapshot UUID
- `IPF_VERIFY` — `True` for valid certificates, `False` for self-signed
- `IPF_TIMEOUT` — request timeout in seconds (default `180`)

### Run the script

```sh
uv run fw_checker.py [OPTIONS]
# or
python fw_checker.py [OPTIONS]
```

Options:

- `--csv PATH` — write the full result set (NOK + OK) to a CSV file
- `--verbose`, `-v` — print connection info

### Examples

Console-only check:

```sh
uv run fw_checker.py
```

Console + CSV export:

```sh
uv run fw_checker.py --csv fw_status.csv
```

### Output

While the script runs you'll see a header showing the target server, snapshot, and tables being collected, plus a small spinner that updates as each fetch step progresses:

```text
IP Fabric Firewall Checker
  Server:   https://ipfabric.example.com
  Snapshot: $last
  Tables:   inventory/devices (devType=fw), security/acl, security/zone-firewall/policies

⠋ Fetching Security > ACL rules...
```

When the fetches complete, two `rich` tables are printed:

- **NOK firewalls** (red) — devices missing rules in both tables
- **OK firewalls** (green) — devices with at least one rule

Each row shows: `hostname | vendor | family | siteName | acl_rules | zone_rules`, sorted by `vendor → family → hostname`. A summary line follows: `N firewalls checked — X OK, Y NOK`.

The CSV (when `--csv` is used) includes the same data plus `status`, `platform`, `model`, and `sn`.

## How matching works

Devices and rules are joined on the **serial number (`sn`)**, not the hostname.

This matters for vendors that present sub-devices (e.g. PaloAlto vsys appear in the inventory as `hostname/vsys1`, `hostname/vsys2`, …). Each sub-device has its own unique `sn`, so they're checked independently.

## Scope

What this script checks:

- ACL rule presence (`/tables/security/acl`)
- Zone-Firewall policy presence (`/tables/security/zone-firewall/policies`)

What it intentionally does **not** check:

- Other security tables (IPS, MPC, NAT, etc.)
- Whether rules actually allow/deny the right traffic
- Per-rule analysis (hit counts, shadowing, etc.)

## License

MIT
