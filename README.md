# zopyx.ssl-cert-check

A tool to check SSL certificate expiration dates.

## Installation

You can install the package using pip:

```bash
pip install .
```

## Usage

The tool checks SSL certificate expiration for a list of domains specified in a configuration file. By default, it looks for a file named `.ssl_domains` in your home directory.

Create a file at `~/.ssl_domains` with the following format:

```
example.com 443
another-domain.com 443
```

Then, run the following command:

```bash
check-ssl-domains
```

You can also provide a path to a different configuration file using the first argument:

```bash
check-ssl-domains /path/to/your/config_file
```
