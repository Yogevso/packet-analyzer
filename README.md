# Packet Analyzer

> **Part of the [Orchestrix Platform](https://github.com/Yogevso/Orchestrix-Platform)** — the network analysis layer for deep packet inspection and anomaly detection.

A low-level network packet analyzer built in C using raw sockets. It captures live Ethernet frames, parses protocol headers (IPv4 / TCP / UDP / ICMP / ARP / DNS), applies user-defined filters, and detects network anomalies including ARP spoofing — all from the command line with live statistics, hex dump, JSON output, and configurable rules.

## Why It Matters

This project demonstrates low-level networking, protocol analysis, anomaly detection, and debugging-oriented systems programming in Linux using raw sockets.

## Features

| Feature | Description | Status |
|---------|-------------|--------|
| **Packet Capture** | Real-time capture via `AF_PACKET` raw socket with interface selection | Implemented |
| **Protocol Parsing** | Ethernet, IPv4, TCP, UDP, ICMP, ARP, DNS header dissection | Implemented |
| **Filtering** | Filter by protocol (`--tcp` / `--udp` / `--icmp` / `--arp`), port, or IP | Implemented |
| **Anomaly Detection** | Oversized packets, suspicious ports, malformed headers, unknown protocols, ARP spoofing | Implemented |
| **Output Modes** | Normal, verbose, quiet (one-line), JSON | Implemented |
| **Color Output** | ANSI color-coded protocol layers | Implemented |
| **Hex Dump** | Raw packet bytes in hex + ASCII | Implemented |
| **Live Statistics** | Real-time packets/sec, bytes/sec, protocol distribution | Implemented |
| **Packet Summary** | Per-protocol breakdown, top IPs, anomaly count on exit | Implemented |
| **DNS Analysis** | Parse DNS queries and responses with query names | Implemented |
| **ARP Spoofing Detection** | Alerts when an IP maps to a different MAC address | Implemented |
| **Configurable Rules** | External config file for anomaly thresholds and suspicious ports | Implemented |
| **Logging** | Write captured output to a log file | Implemented |
| **Traffic Replay** | Record packets to binary file and replay later | Implemented |
| **Unit Tests** | Parser and analyzer tests with `make test` | Implemented |
| **PCAP Export** | Export captures in `.pcap` format for Wireshark interop | Planned |

## Build

```bash
make          # build the sniffer
make test     # run unit tests
make clean    # clean build artifacts
```

Requires GCC and a Linux environment (uses `AF_PACKET`).

## Usage

**Must run as root** (raw sockets require `CAP_NET_RAW`):

```bash
# Capture all traffic
sudo ./sniffer

# Capture on specific interface
sudo ./sniffer --iface eth0

# TCP only, port 443, with color
sudo ./sniffer --tcp --port 443 --color

# UDP traffic with verbose output
sudo ./sniffer --udp --verbose --color

# ICMP only (ping traffic)
sudo ./sniffer --icmp --color

# ARP traffic only
sudo ./sniffer --arp --color

# Filter by IP address
sudo ./sniffer --ip 192.168.1.1

# Quiet mode (one line per packet)
sudo ./sniffer --quiet --color

# JSON output (for scripting / piping)
sudo ./sniffer --json

# Hex dump of each packet
sudo ./sniffer --hex --count 10

# Live statistics dashboard
sudo ./sniffer --stats

# Log to file + custom anomaly rules
sudo ./sniffer --log traffic.log --anomaly-config anomaly.conf

# Capture first 100 packets
sudo ./sniffer --count 100

# Record traffic for later replay
sudo ./sniffer --record capture.bin

# Replay recorded traffic
./sniffer --replay capture.bin
```

### CLI Options

| Option | Description |
|--------|-------------|
| **Capture** | |
| `--iface IFACE` | Capture on specific interface (e.g. `eth0`) |
| `--count N` | Stop after capturing N packets |
| `--record FILE` | Save raw packets to binary file |
| `--replay FILE` | Replay packets from a recorded file |
| **Filters** | |
| `--tcp` | Show only TCP packets |
| `--udp` | Show only UDP packets |
| `--icmp` | Show only ICMP packets |
| `--arp` | Show only ARP packets |
| `--port PORT` | Filter by port number |
| `--ip ADDRESS` | Filter by IPv4 address (source or destination) |
| **Output** | |
| `--verbose` | Show all header fields |
| `--quiet` | One-line-per-packet summary |
| `--json` | JSON output (one object per line) |
| `--hex` | Show hex dump of each packet |
| `--color` | Enable ANSI colored output |
| `--stats` | Show live statistics (packets/sec, protocol breakdown) |
| `--log FILE` | Append output to log file |
| **Anomaly** | |
| `--anomaly-config FILE` | Load anomaly detection rules from config file |
| `-h`, `--help` | Show help message |

## Example Output

### Normal Mode
```
──────────────────────────────────────
Packet #1
[ETH] aa:bb:cc:dd:ee:01 → ff:ee:dd:cc:bb:02 | Type: 0x0800
[IP]  192.168.1.2 → 142.250.74.14 | Proto: TCP | TTL: 64
[TCP] 52344 → 443 | Flags: SYN | Seq: 2981734021
Size: 74 bytes
```

### Quiet Mode
```
#1       74 B  TCP 192.168.1.2:52344 → 142.250.74.14:443 [SYN]
#2       42 B  ARP Request 192.168.1.1 → 192.168.1.2
#3       98 B  ICMP 10.0.0.1 → 10.0.0.2 Echo Request
#4       85 B  UDP 192.168.1.5:12345 → 8.8.8.8:53
```

### JSON Mode
```json
{"packet":1,"size":74,"eth":{"src":"aa:bb:cc:dd:ee:01","dst":"ff:ee:dd:cc:bb:02","type":"0x0800"},"ip":{"src":"192.168.1.2","dst":"142.250.74.14","proto":"TCP","ttl":64},"tcp":{"src_port":52344,"dst_port":443,"flags":"SYN","seq":2981734021}}
```

### DNS Parsing
```
[DNS] Query | ID: 43981 | Name: example.com | Type: A
[DNS] Response | ID: 43981 | Answers: 1 | Query: example.com (A)
```

### Anomaly Warnings
```
[WARNING] Large packet detected (9000 bytes, threshold 1500)
[WARNING] Suspicious destination port: 23
[WARNING] Unknown/uncommon IP protocol: 47
[ALERT] ARP spoofing detected! IP 192.168.1.1 changed from aa:bb:cc:dd:ee:01 to ff:ff:ff:ff:ff:ff
```

### Capture Summary (on exit)
```
╔══════════════════════════════════════╗
║         CAPTURE SUMMARY              ║
╠══════════════════════════════════════╣
║  Duration     : 45 seconds
║  Total Packets: 1284
║  Total Bytes  : 856320
║  Packets/sec  : 28.5
║  Bytes/sec    : 19029.3
╠══════════════════════════════════════╣
║  TCP   : 892
║  UDP   : 234
║  ICMP  : 45
║  ARP   : 98
║  DNS   : 67
║  Other : 15
╠══════════════════════════════════════╣
║  Anomalies    : 3
╠══════════════════════════════════════╣
║  Top Source IPs:
║    192.168.1.2        456 pkts
║    10.0.0.5           234 pkts
║  Top Destination IPs:
║    8.8.8.8            189 pkts
║    142.250.74.14      145 pkts
╚══════════════════════════════════════╝
```

## Project Structure

```
packet-analyzer/
├── src/
│   ├── main.c          # CLI entry point, capture loop
│   ├── sniffer.c       # Raw socket creation, capture, record/replay
│   ├── parser.c        # Ethernet/IP/TCP/UDP/ICMP/ARP/DNS parsing
│   ├── filters.c       # Filter matching logic
│   ├── analyzer.c      # Anomaly detection + ARP spoofing + config
│   ├── output.c        # Output formatting (normal/verbose/quiet/JSON/hex/color)
│   └── stats.c         # Packet statistics + live stats
├── include/
│   ├── sniffer.h
│   ├── parser.h
│   ├── filters.h
│   ├── analyzer.h
│   ├── output.h
│   └── stats.h
├── tests/
│   └── test_parser.c   # Unit tests for parsers, filters, anomaly detection
├── docs/
│   ├── PRD.md
│   ├── design.md
│   └── debugging_case.md
├── logs/
├── anomaly.conf        # Example anomaly detection config
├── Makefile
├── LICENSE
└── README.md
```

## Architecture

```
CLI Interface  →  Packet Capture  →  Protocol Parser  →  Filter Engine  →  Analyzer  →  Output
   (main.c)       (sniffer.c)        (parser.c)         (filters.c)     (analyzer.c)   (output.c)
                                                                             ↓
                                                                        Statistics
                                                                        (stats.c)
```

Each layer is cleanly separated with its own header and source file. The main loop orchestrates the pipeline: **capture → parse → filter → display → analyze → record → stats**.

## Anomaly Detection

The analyzer flags:
- **Large packets** — size exceeding configurable threshold (default: 1500 bytes)
- **Suspicious ports** — configurable list (default: Telnet/23, FTP/21, rlogin/513)
- **Malformed headers** — invalid IHL, inconsistent total_length
- **Unknown protocols** — IP protocol numbers other than TCP/UDP/ICMP
- **ARP spoofing** — detects when an IP address maps to a different MAC (cache-based)

All rules can be toggled and configured via `anomaly.conf`:

```ini
large_packet_threshold=1500
check_arp_spoofing=1
suspicious_port=23
suspicious_port=3389
```

## Unit Tests

Run `make test` to execute all parser and analyzer unit tests:

```
=== Packet Analyzer Unit Tests ===

test_parse_ethernet...
test_parse_ip...
test_parse_tcp...
test_parse_udp...
test_parse_icmp...
test_parse_arp...
test_parse_dns...
test_ip_to_str...
test_tcp_flags_to_str...
test_mac_to_str...
test_protocol_name...
test_icmp_type_name...
test_filter_match...
test_anomaly_config...
test_check_large_packet...
test_check_unknown_protocol...
test_arp_spoofing...

=== Results: 50/50 passed ===
```

## Documentation

- [PRD](docs/PRD.md) — Product requirements
- [Design](docs/design.md) — Architecture and module design
- [Debugging Case Study](docs/debugging_case.md) — Example real-world usage scenario

## License

See [LICENSE](LICENSE) for details.
