# NetRecon — TCP Network Scanner

A multi-threaded TCP port scanner with banner grabbing, service identification, and CIDR range support. Built with Python's standard library — no external dependencies.

## Features

- Multi-threaded concurrent scanning
- CIDR range expansion, capped at /22 so a typo cannot start a 16-million-host sweep
- Service banner grabbing and service-name lookup for well-known ports
- Distinguishes open, closed and filtered (no response) ports
- OS hints based on the mix of open ports — a guess, not a fingerprint
- JSON report export
- A self-contained `--demo` that starts its own listeners on localhost

## Quick start

```bash
# Self-contained demo: starts two listeners on 127.0.0.1 and scans them.
# Nothing leaves your machine. This is the fastest way to see it work.
python scanner.py --demo
```

## Usage

```bash
# Scan a single host across the built-in common ports
python scanner.py -t 127.0.0.1

# Specific ports and ranges
python scanner.py -t 127.0.0.1 --ports 22,80,443,8000-8010

# A subnet you are responsible for (max /22)
python scanner.py -t 192.168.1.0/24 --ports 22,80,443,8080

# Every port, 1-65535 (slow)
python scanner.py -t 127.0.0.1 --full

# Save results to JSON
python scanner.py -t 127.0.0.1 --output report.json

# Turn the thread count down on a fragile or rate-limited network
python scanner.py -t 127.0.0.1 --threads 20

# Give each port longer to answer, over a slow link (default: 1.0s, 3.0s on Windows)
python scanner.py -t 127.0.0.1 --timeout 5
```

Invalid input is rejected before any socket is opened, and the program exits with status 2:

```
$ python scanner.py -t 999.1.1.1
[!] '999.1.1.1' is not a valid IP address or CIDR range

$ python scanner.py -t 10.0.0.0/8
[!] 10.0.0.0/8 covers 16777216 addresses; NetRecon refuses anything wider than /22 (1024 addresses). Split it into smaller blocks.

$ python scanner.py -t 127.0.0.1 --timeout 0
[!] --timeout must be greater than 0 (got 0.0). A zero or negative budget reports every port as closed.
```

### Why `--timeout` defaults differently per platform

The connect budget decides how NetRecon tells a *closed* port from a *filtered*
one, and the two operating systems disagree about how fast they will admit a
port is closed.

Linux answers a connection attempt on a closed port with an immediate RST, so
`ConnectionRefusedError` arrives in milliseconds. Windows retransmits the SYN
before surfacing `WSAECONNREFUSED` — measured on loopback at **2.011s**, against
a **1.005s** timeout. With a single 1.0s budget the timeout always won, so on
Windows every closed port was reported as "filtered", inverting the feature this
tool advertises. The default is therefore 1.0s on POSIX and 3.0s on Windows, and
`--timeout` overrides it.

That is also why a zero or negative value is refused rather than passed through:
it does not raise an error at the socket layer on every platform, it just makes
every port look closed and hands back a confident, wrong all-clear.

## How it works (plain English)

**The problem it solves.** Every computer on a network has thousands of numbered "doors" called ports. Software opens a door when it wants to accept connections — a web server opens door 80, a remote-login service opens door 22. Over time machines end up with doors open that nobody remembers opening: a database left reachable, a test service someone forgot to switch off. Those are the doors an attacker looks for first. NetRecon tells you which doors are open on a machine you are responsible for, so you can close the ones that should not be.

**What a port scan actually is.** It is knocking. For each port, the scanner tries to start an ordinary TCP connection, exactly like a browser does. If something answers, the port is open. If the machine actively replies "nothing here", it is closed. If nothing comes back at all before the timeout, it is filtered — usually a firewall silently dropping the knock. NetRecon does not exploit anything and does not send malformed traffic; it only completes normal connections and, where a service volunteers a greeting, notes what it said.

**Try it without touching anyone else's network.** Run `python scanner.py --demo`. The tool starts two small listeners inside its own process on `127.0.0.1` (your own machine — an address that cannot be reached from outside), scans a short list of ports, and finds them. Not one packet leaves your computer, and it always finds at least one open port, so you see real output immediately.

**Reading the output.** Each open or filtered port is one row:

```
  36289  OPEN      unknown  SSH-2.0-NetRecon_Demo
```

| Column | Meaning |
| --- | --- |
| `36289` | The port number — which numbered door answered. |
| `OPEN` | The state. `OPEN` means something is listening. `FILTERED` means no answer at all, usually a firewall. `ERROR` means the probe itself failed — for example the scanner ran out of file descriptors under a high `--threads` count — so the port's true state is unknown and is deliberately *not* reported as closed. Closed ports are not printed; on a normal scan nearly everything is closed and listing them would bury the result. |
| `unknown` | The service usually found on that port, from a built-in table. `unknown` only means the port is not in the table — it says nothing about what is really running there. |
| `SSH-2.0-NetRecon_Demo` | The banner: the greeting the service sent back, often naming the software and version. Blank when the service says nothing. |

The summary at the end gives the elapsed time, how many ports were open, and which ones.

**What an open port implies for security.** An open port is not a vulnerability by itself — a web server is supposed to have port 80 open. It is an entry point, and it matters for three reasons: it is one more piece of software that can be attacked; the banner may reveal an old, known-vulnerable version; and it may be something that was never meant to be reachable at all, such as a database exposed to the whole office network instead of just the application server. The useful question is not "is anything open" but "is everything that is open supposed to be open, patched, and reachable only by the people who need it".

**When someone would legitimately use this.** Checking what your own laptop or server exposes. Confirming a firewall rule actually took effect. Building an inventory of what is running on a network you administer. Verifying that a service you shut down really did stop listening. A penetration tester doing the same on a client's network — with a signed scope document. Outside cases like those, do not run it.

## Requirements

- Python 3.10 or newer, no external packages (pure standard library)
- Developed and tested on Python 3.14 on Linux

## Running the tests

```bash
python3 -m unittest discover -v
```

The tests only ever talk to `127.0.0.1` — they start their own listeners and scan those. Nothing reaches the network, and no test depends on an external DNS server.

## Ethical use

**Only scan systems you own, or systems you have explicit written authorisation to test.**

Port scanning someone else's machine without permission is at best unwelcome and in many countries illegal — it can fall foul of the US Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalents elsewhere. "I was only looking" is not a defence, and scans are logged at the far end with your IP address on them.

Before scanning anything that is not yours:

- Get authorisation in writing, from someone with the authority to give it.
- Agree the exact scope — which addresses, which ports, which dates.
- Stay inside that scope. Do not follow the network somewhere interesting.

Deliberately, this repository contains no examples pointed at third-party hosts, and `--demo` refuses to scan anything but loopback. If you are unsure whether you are allowed to scan a target, you are not allowed to scan it.
