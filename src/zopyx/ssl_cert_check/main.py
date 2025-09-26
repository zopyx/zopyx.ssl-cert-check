import asyncio
import ssl
import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import argparse
from typing import Union, List, Tuple
import re
import importlib.metadata
import ipaddress

__version__ = importlib.metadata.version('zopyx.ssl-cert-check')


def validate_domain(domain: str) -> bool:
    """Validate domain name format."""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain)) and len(domain) <= 253


def validate_port(port_str: str) -> int:
    """Validate and return port number."""
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError(f"Port {port} out of valid range (1-65535)")
        return port
    except ValueError as e:
        raise ValueError(f"Invalid port '{port_str}': {e}")


def parse_domains_file(config_file: Path) -> List[Tuple[str, int]]:
    """Parse domains configuration file and return list of (domain, port) tuples."""
    domains = []
    
    with open(config_file, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            parts = line.split()
            if not parts:
                continue
                
            domain = parts[0]
            
            # Validate domain
            if not validate_domain(domain):
                print(f"Warning: Invalid domain '{domain}' on line {line_num}, skipping")
                continue
            
            # Handle port
            if len(parts) == 1:
                port = 443
            else:
                try:
                    port = validate_port(parts[1])
                except ValueError as e:
                    print(f"Warning: {e} on line {line_num}, using port 443")
                    port = 443
            
            domains.append((domain, port))
    
    return domains


def is_ip_address(host: str) -> bool:
    """Check if the host is a valid IP address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_private_ip(host: str) -> bool:
    """Check if host is a private/internal IP address."""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        # Not an IP address, assume it's a hostname
        return False


async def get_cert_expiry_date(host: str, port: int, timeout: int = 5, allow_private_ips: bool = False) -> Union[datetime.datetime, str]:
    """
    Get SSL certificate expiry date for a given host and port.
    
    Args:
        host: The hostname to check
        port: The port number
        timeout: Connection timeout in seconds
        allow_private_ips: Whether to allow connections to private IP addresses
        
    Returns:
        datetime.datetime: The expiry date if successful (timezone-aware UTC)
        str: Error message if failed
    """
    # SECURITY: Check for private IP addresses to prevent SSRF
    if not allow_private_ips and is_private_ip(host):
        return "Blocked: Private IP address (use --allow-private-ips to override)"
    
    try:
        # Create secure SSL context with explicit settings
        ssl_context = ssl.create_default_context()
        
        # SECURITY: Explicitly set minimum TLS version
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        is_ip = is_ip_address(host)
        
        # SECURITY: Ensure hostname verification is enabled for hostnames
        ssl_context.check_hostname = not is_ip
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # For hostnames, pass server_hostname for SNI. Not applicable for IPs.
        server_hostname = host if not is_ip else None
        
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context, server_hostname=server_hostname), timeout=timeout
        )
        cert = writer.get_extra_info("peercert")
        
        if not cert:
            writer.close()
            await writer.wait_closed()
            return "No certificate found"
        
        # Try different date formats
        not_after = cert.get("notAfter")
        if not not_after:
            writer.close()
            await writer.wait_closed()
            return "Certificate missing expiry date"
        
        try:
            # SECURITY: Parse certificate date as UTC timezone-aware
            expiry_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            try:
                expiry_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
                expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)
            except ValueError as e:
                writer.close()
                await writer.wait_closed()
                return f"Unable to parse certificate date: {e}"
        
        writer.close()
        await writer.wait_closed()
        return expiry_date
        
    except ssl.SSLError as e:
        return f"SSL Error: {str(e)}"
    except ConnectionRefusedError:
        return "Connection refused"
    except asyncio.TimeoutError:
        return f"Timeout after {timeout}s"
    except OSError as e:
        return f"Network error: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


async def main_async() -> None:
    """Main async function to check SSL certificates."""
    parser = argparse.ArgumentParser(
        description="Check SSL certificate expiration for a list of domains."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show program's version number and exit.",
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
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--allow-private-ips",
        action="store_true",
        help="Allow connections to private IP addresses (SECURITY WARNING: may enable SSRF)",
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=50,
        help="Maximum concurrent connections (default: 50)",
    )
    args = parser.parse_args()

    config_file = Path(args.config_file)
    if not config_file.exists():
        print(f"Error: Configuration file not found at {config_file}")
        print(f"Create a file at {config_file} with domains and ports:")
        print("example.com 443")
        print("another-domain.com 443")
        return

    try:
        domains = parse_domains_file(config_file)
    except Exception as e:
        print(f"Error reading configuration file: {e}")
        return

    if not domains:
        print("No valid domains found in configuration file")
        return

    if args.verbose:
        print(f"Checking {len(domains)} domains with timeout {args.timeout}s")
        print(f"Max concurrent connections: {args.max_concurrent}")
        if args.allow_private_ips:
            print("WARNING: Private IP connections are enabled (potential SSRF risk)")

    console = Console()
    table = Table(title="SSL Certificate Expiration Check")
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Port", style="magenta", justify="right")
    table.add_column("Expires In (Days)", style="green", justify="right")
    table.add_column("Status", style="yellow")

    rows = []
    with Progress() as progress:
        task = progress.add_task("[green]Checking domains...", total=len(domains))
        
        # SECURITY: Limit concurrent connections to prevent resource exhaustion
        semaphore = asyncio.Semaphore(args.max_concurrent)
        
        async def check_with_semaphore(host, port):
            async with semaphore:
                return await get_cert_expiry_date(host, port, timeout=args.timeout, allow_private_ips=args.allow_private_ips)
        
        tasks = [
            check_with_semaphore(host, port)
            for host, port in domains
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for (host, port), result in zip(domains, results):
            # Handle exceptions from asyncio.gather
            if isinstance(result, Exception):
                expiry_date = f"Unexpected error: {str(result)}"
            else:
                expiry_date = result
                
            # SECURITY: Use timezone-aware UTC for accurate comparison
            now = datetime.datetime.now(datetime.timezone.utc)
            if isinstance(expiry_date, datetime.datetime):
                delta = expiry_date - now
                days_left = delta.days
                
                # Color coding based on days left
                if days_left < 0:
                    status = f"[bold red]EXPIRED ({abs(days_left)} days ago)[/bold red]"
                elif days_left < 7:
                    status = f"[bold red]CRITICAL ({days_left} days)[/bold red]"
                elif days_left < 30:
                    status = f"[bold yellow]WARNING ({days_left} days)[/bold yellow]"
                else:
                    status = f"[bold green]OK ({days_left} days)[/bold green]"
                    
                rows.append((host, str(port), days_left, status))
            else:
                rows.append((host, str(port), -999, f"[bold red]Error: {expiry_date}[/bold red]"))
            
            progress.update(task, advance=1)

    # Sort by days left (errors at the end)
    rows.sort(key=lambda x: x[2])

    for row in rows:
        host, port, days_left, status = row
        days_display = str(days_left) if days_left != -999 else "N/A"
        table.add_row(host, port, days_display, status)

    console.print(table)
    
    # Summary
    total_domains = len(domains)
    expired = sum(1 for _, _, days, _ in rows if isinstance(days, int) and days < 0)
    critical = sum(1 for _, _, days, _ in rows if isinstance(days, int) and 0 <= days < 7)
    warning = sum(1 for _, _, days, _ in rows if isinstance(days, int) and 7 <= days < 30)
    errors = sum(1 for _, _, days, _ in rows if days == -999)
    
    console.print(f"\n[bold]Summary:[/bold] {total_domains} domains checked")
    if expired > 0:
        console.print(f"[bold red]• {expired} expired certificates[/bold red]")
    if critical > 0:
        console.print(f"[bold red]• {critical} certificates expiring within 7 days[/bold red]")
    if warning > 0:
        console.print(f"[bold yellow]• {warning} certificates expiring within 30 days[/bold red]")
    if errors > 0:
        console.print(f"[bold red]• {errors} domains with errors[/bold red]")


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()