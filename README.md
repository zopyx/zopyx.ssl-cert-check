# zopyx.ssl-cert-check

A tool to check SSL certificate expiration dates.

## Installation

You can install the package using `pip` or `uv`.

### Using pip

```bash
pip install .
```

### Using uv

```bash
uv pip install .
```

## Usage

The tool checks SSL certificate expiration for a list of domains specified in a configuration file.

### Default configuration

By default, it looks for a file named `.ssl_domains` in your home directory.

Create a file at `~/.ssl_domains` with the following format (domain and port on each line):

```
example.com 443
another-domain.com 443
```

Then, run the following command:

```bash
check-ssl-domains
```

### Custom configuration file

You can also provide a path to a different configuration file using the first argument:

```bash
check-ssl-domains /path/to/your/config_file
```

The format of the configuration file is the same as the default one.

### Security Options

The tool includes several security-focused options:

```bash
# Allow connections to private IP addresses (use with caution)
check-ssl-domains --allow-private-ips

# Limit concurrent connections (default: 50)
check-ssl-domains --max-concurrent 20

# Set connection timeout (default: 5 seconds)
check-ssl-domains --timeout 10
```

**Security Note**: By default, the tool blocks connections to private IP addresses to prevent Server-Side Request Forgery (SSRF) attacks. Only use `--allow-private-ips` if you need to check internal services and understand the security implications.

### Example output

The tool will print a table with the host, port, days until expiration, and the status:

```
| Host               | Port | Expires In (Days) | Status      |
|--------------------|------|-------------------|-------------|
| example.com        | 443  | 30                | 30 days     |
| another-domain.com | 443  | 60                | 60 days     |
```

## License

MIT

## Copyright

(C) 2025 by Andreas Jung
