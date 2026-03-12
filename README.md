# NetRecon — TCP Network Scanner

A multi-threaded TCP port scanner with banner grabbing, service identification, and CIDR range support. Built with Python's standard library — no external dependencies.

## Features

- Multi-threaded concurrent scanning for speed
- CIDR range expansion and subnet enumeration
- Service banner grabbing and version identification
- Configurable port ranges and timeout values
- OS fingerprinting hints based on open ports
- JSON report export

## Usage

```bash
# Scan a single host (top 20 common ports)
python scanner.py -t 192.168.1.1

# Scan a CIDR range with specific ports
python scanner.py -t 192.168.1.0/24 --ports 22,80,443,8080

# Full scan (ports 1-1024)
python scanner.py -t scanme.nmap.org --full

# Save results to JSON
python scanner.py -t 10.0.0.1 --output report.json
```

## Requirements

- Python 3.10+
- No external dependencies (pure stdlib)

## Ethical Use

Only scan systems you own or have explicit written permission to test. Unauthorized scanning may violate the CFAA or other applicable laws.
