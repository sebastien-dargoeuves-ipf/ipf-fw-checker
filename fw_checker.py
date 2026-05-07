# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "ipfabric",
#     "python-dotenv",
#     "rich",
# ]
# ///
"""IP Fabric Firewall Checker.

Lists every device of type `fw` from Inventory > Devices and verifies that
each has at least one rule in either:
  - Technology > Security > ACL
  - Technology > Security > Zone Firewall (Policies)

Devices with zero rules in both tables are reported as NOK.
"""

import argparse
import csv
import os
import sys
from collections import Counter
from typing import List, Optional

from dotenv import find_dotenv, load_dotenv
from ipfabric import IPFClient
from rich.console import Console
from rich.table import Table

console = Console()

DEVICE_COLUMNS = ["hostname", "sn", "vendor", "family", "platform", "model", "siteName"]
OUTPUT_COLUMNS = [
    "status",
    "hostname",
    "vendor",
    "family",
    "platform",
    "model",
    "siteName",
    "acl_rules",
    "zone_rules",
    "sn",
]


def fetch_rule_counts(ipf: IPFClient, url: str) -> Counter:
    """Return a Counter of rule rows keyed by device serial number."""
    rows = ipf.fetch_all(url, columns=["sn"])
    return Counter(r["sn"] for r in rows if r.get("sn"))


def classify(firewalls: List[dict], acl_counts: Counter, zone_counts: Counter):
    ok, nok = [], []
    for fw in firewalls:
        sn = fw.get("sn")
        a = acl_counts.get(sn, 0)
        z = zone_counts.get(sn, 0)
        record = {
            **fw,
            "acl_rules": a,
            "zone_rules": z,
            "status": "OK" if (a + z) > 0 else "NOK",
        }
        if record["status"] == "OK":
            ok.append(record)
        else:
            nok.append(record)
    sort_key = lambda r: (r.get("vendor") or "", r.get("family") or "", r.get("hostname") or "")
    return sorted(ok, key=sort_key), sorted(nok, key=sort_key)


def render_table(title: str, rows: List[dict], style: str) -> Table:
    table = Table(title=title, header_style=f"bold {style}", title_style=f"bold {style}")
    for col in ["hostname", "vendor", "family", "siteName", "acl_rules", "zone_rules"]:
        justify = "right" if col.endswith("_rules") else "left"
        table.add_column(col, justify=justify)
    for r in rows:
        table.add_row(
            str(r.get("hostname", "")),
            str(r.get("vendor", "")),
            str(r.get("family", "")),
            str(r.get("siteName", "")),
            str(r.get("acl_rules", 0)),
            str(r.get("zone_rules", 0)),
        )
    return table


def write_csv(path: str, rows: List[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in OUTPUT_COLUMNS})


def main(csv_output: Optional[str] = None, verbose: bool = False) -> None:
    """Check which firewalls are missing security rules in IP Fabric."""
    load_dotenv(find_dotenv(), override=True)

    ipf_url = os.getenv("IPF_URL")
    ipf_token = os.getenv("IPF_TOKEN")
    if not ipf_url or not ipf_token:
        console.print("[red]Missing IPF_URL or IPF_TOKEN in .env[/red]")
        sys.exit(2)

    snapshot = os.getenv("IPF_SNAPSHOT", "$last")
    console.print("[bold]IP Fabric Firewall Checker[/bold]")
    console.print(f"  Server:   [cyan]{ipf_url}[/cyan]")
    console.print(f"  Snapshot: [cyan]{snapshot}[/cyan]")
    console.print(
        "  Tables:   inventory/devices (devType=fw), "
        "security/acl, security/zone-firewall/policies\n"
    )

    with console.status("[cyan]Connecting to IP Fabric...[/cyan]") as status:
        ipf = IPFClient(
            base_url=ipf_url,
            token=ipf_token,
            snapshot_id=snapshot,
            verify=(os.getenv("IPF_VERIFY", "False") == "True"),
            timeout=int(os.getenv("IPF_TIMEOUT", 180)),
        )
        if verbose:
            console.print(f"Connected — snapshot id {ipf.snapshot_id}")

        status.update("[cyan]Fetching firewalls from Inventory > Devices...[/cyan]")
        firewalls = ipf.inventory.devices.all(
            filters={"devType": ["eq", "fw"]},
            columns=DEVICE_COLUMNS,
        )
        if not firewalls:
            console.print("[yellow]No firewalls (devType=fw) found in this snapshot.[/yellow]")
            return

        status.update("[cyan]Fetching Security > ACL rules...[/cyan]")
        acl_counts = fetch_rule_counts(ipf, "/tables/security/acl")

        status.update("[cyan]Fetching Security > Zone Firewall policies...[/cyan]")
        zone_counts = fetch_rule_counts(ipf, "/tables/security/zone-firewall/policies")

    ok, nok = classify(firewalls, acl_counts, zone_counts)

    if nok:
        console.print(render_table(f"NOK firewalls ({len(nok)})", nok, "red"))
    else:
        console.print("[green]All firewalls have at least one rule.[/green]")

    if ok:
        console.print(render_table(f"OK firewalls ({len(ok)})", ok, "green"))

    console.print(
        f"\n[bold]{len(firewalls)} firewalls checked — "
        f"[green]{len(ok)} OK[/green], [red]{len(nok)} NOK[/red][/bold]"
    )

    if csv_output:
        write_csv(csv_output, nok + ok)
        console.print(f"\nCSV written to [cyan]{csv_output}[/cyan]")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check which firewalls are missing security rules in IP Fabric."
    )
    parser.add_argument(
        "--csv",
        dest="csv_output",
        default=None,
        metavar="PATH",
        help="Write full results to a CSV file.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output."
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    main(csv_output=args.csv_output, verbose=args.verbose)
