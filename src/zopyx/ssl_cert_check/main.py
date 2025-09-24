import asyncio
import ssl
import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import argparse


async def get_cert_expiry_date(host, port, timeout=5):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=True), timeout=timeout
        )
        cert = writer.get_extra_info("peercert")
        expiry_date = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        )
        writer.close()
        await writer.wait_closed()
        return expiry_date
    except (ssl.SSLError, ConnectionRefusedError, OSError, asyncio.TimeoutError) as e:
        return e


async def main_async():
    parser = argparse.ArgumentParser(
        description="Check SSL certificate expiration for a list of domains."
    )
    parser.add_argument(
        "config_file",
        nargs="?",
        default=f"{Path.home()}/.ssl_domains",
        help="Path to the configuration file (default: ~/.ssl_domains)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=5,
        help="Timeout in seconds for each host check (default: 5)",
    )
    args = parser.parse_args()

    config_file = Path(args.config_file)
    if not config_file.exists():
        print(f"Error: Configuration file not found at {config_file}")
        return

    with open(config_file, "r") as f:
        domains = [line.strip().split() for line in f if line.strip()]

    console = Console()
    table = Table(title="SSL Certificate Expiration Check")
    table.add_column("Host", style="cyan")
    table.add_column("Port", style="magenta")
    table.add_column("Expires In (Days)", style="green")
    table.add_column("Status", style="yellow")

    with Progress() as progress:
        task = progress.add_task("[green]Checking domains...", total=len(domains))
        tasks = [
            get_cert_expiry_date(host, int(port), timeout=args.timeout)
            for host, port in domains
        ]
        results = await asyncio.gather(*tasks)
        for (host, port), expiry_date in zip(domains, results):
            now = datetime.datetime.now()
            if isinstance(expiry_date, datetime.datetime):
                delta = expiry_date - now
                days_left = delta.days
                if days_left < 30:
                    status = f"[bold red]{days_left} days[/bold red]"
                else:
                    status = f"[bold green]{days_left} days[/bold green]"
                table.add_row(host, port, str(days_left), status)
            else:
                table.add_row(
                    host, port, "N/A", f"[bold red]Error: {expiry_date}[/bold red]"
                )
            progress.update(task, advance=1)

    console.print(table)


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
