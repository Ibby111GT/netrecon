# port definitions and scan defaults
# pulled these out of scanner.py to keep things clean

import sys

# Linux sends an RST for a closed port on the first SYN, so ConnectionRefusedError
# lands in a few milliseconds. Windows retransmits the SYN before surfacing
# WSAECONNREFUSED — measured on loopback at 2.011s, against a TimeoutError at
# 1.005s — so a 1.0s budget expires first and every closed port is misreported as
# "filtered". That inverts the tool's headline claim, so the default is
# platform-dependent. Override per run with --timeout.
CONNECT_TIMEOUT = 3.0 if sys.platform == "win32" else 1.0
BANNER_TIMEOUT  = 2.0
MAX_THREADS     = 200

# upper bound on --threads; past this you are just thrashing the scheduler
THREAD_LIMIT = 1000

# widest CIDR block we will expand. /22 is 1024 addresses, which covers a
# realistic subnet sweep — anything wider is nearly always a typo, and
# expanding it looks exactly like the tool has hung.
MIN_CIDR_PREFIX = 22

# top services worth checking on most engagements
COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}
