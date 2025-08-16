You are an python Expert developer.

Write a Python package "zopyx.ssl-cert-check" that
takes a config file with hostname and ports like 
$HOME/.ssl_domains with format:


www.zchl.uni-sb.de 443
admin.zchl.uni-sb.de 443
zopyx.com 443
www.zopyx.com 443
www.produce-and-publish.info 443


The package provides a commandline script "check-ssl-domains" that
- reads the file
- checks the host for their cert expiration
- all checks in parallel
- progress report with a visual progress bar
- report as a table using rich.Table

Use "uv" for all packaging tasks, nothing else
