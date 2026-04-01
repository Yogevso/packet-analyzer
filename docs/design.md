# Design Document — Packet Analyzer

## Architecture Overview

```
+──────────────────────────+
│   CLI Interface          │  (main.c — argument parsing, signal handling)
+────────────┬─────────────+
             │
             v
+──────────────────────────+
│ Packet Capture Layer     │  (sniffer.c — AF_PACKET raw socket, record/replay)
+────────────┬─────────────+
             │
             v
+──────────────────────────+
│ Protocol Parser          │  (parser.c — Eth/IP/TCP/UDP/ICMP/ARP/DNS)
+────────────┬─────────────+
             │
             v
+──────────────────────────+
│ Filter Engine            │  (filters.c — protocol/port/IP/EtherType matching)
+────────────┬─────────────+
             │
             v
+──────────────────────────+
│ Output Formatter         │  (output.c — normal/verbose/quiet/JSON/hex/color)
+────────────┬─────────────+
             │
             v
+──────────────────────────+
│ Analyzer Engine          │  (analyzer.c — anomaly detection, ARP spoofing, config)
+────────────┬─────────────+
             │
             v
+──────────────────────────+
│ Statistics Engine        │  (stats.c — counters, top IPs, live stats, summary)
+──────────────────────────+
```

## Module Responsibilities

### sniffer.c / sniffer.h
- Creates `AF_PACKET` raw socket (`SOCK_RAW`, `ETH_P_ALL`)
- Supports binding to a specific interface via `--iface` (uses `ioctl(SIOCGIFINDEX)` + `bind()`)
- Captures raw Ethernet frames via `recvfrom()`
- Supports binary record (write) and replay (read) of packets

### parser.c / parser.h
- Parses Ethernet (14-byte header → MACs + EtherType)
- Parses IPv4 (20+ byte header → addresses, protocol, TTL, etc.)
- Parses TCP (ports, flags, sequence numbers)
- Parses UDP (ports, length)
- Parses ICMP (type, code, ID, sequence — Echo Request/Reply, Dest Unreachable, etc.)
- Parses ARP (28-byte Ethernet/IPv4 — sender/target MAC and IP, opcode)
- Parses DNS (header + query name decoding via label pointers, type, answer count)
- Utility functions: `ip_to_str()`, `mac_to_str()`, `tcp_flags_to_str()`, `protocol_name()`, `icmp_type_name()`, `arp_opcode_name()`, `dns_type_name()`

### filters.c / filters.h
- Holds a `filter_config_t` struct with TCP/UDP/ICMP/ARP/port/IP criteria
- `filter_match()` accepts an `ethertype` parameter for ARP (non-IP) filtering
- Uses goto-based logic to support multiple exclusive protocol filters
- IP parsing helper for CLI argument conversion

### analyzer.c / analyzer.h
- **Configurable anomaly detection** via `anomaly_config_t` struct loaded from config file
- `check_large_packet()` — warns if size exceeds configurable threshold
- `check_malformed_ip()` — validates IHL, total_length consistency
- `check_suspicious_port()` — checks against configurable port list (default: 23, 21, 513)
- `check_unknown_protocol()` — warns on non-TCP/UDP/ICMP protocols
- `check_arp_spoofing()` — maintains IP→MAC cache, alerts on MAC changes for known IPs
- `anomaly_config_load()` — parses key=value config file for thresholds and toggles
- `analyze_packet()` returns anomaly count per packet

### output.c / output.h
- **Normal mode** — layered protocol output with optional ANSI color
- **Verbose mode** — prints all header fields including TTL, window size, checksum, etc.
- **Quiet mode** — one-line-per-packet summary (size, protocol, endpoints, flags)
- **JSON mode** — structured single-line JSON object per packet
- **Hex dump** — offset / hex bytes / ASCII display
- **Color** — ANSI codes: cyan (ETH), green (IP), yellow (TCP), magenta (UDP), blue (ICMP), red (ARP), white (DNS)
- `emit()` helper writes to both stdout and optional log file

### stats.c / stats.h
- Tracks per-protocol packet counts (TCP, UDP, ICMP, ARP, DNS, other)
- Tracks total bytes and anomaly count
- IP hash table tracking top source and destination IPs
- `stats_print_live()` — single-line real-time update (packets/sec, bytes/sec, distribution)
- `stats_print_summary()` — box-drawn capture summary on exit (duration, rates, top 5 IPs)

### main.c
- CLI argument parsing (20+ options via manual loop)
- Signal handling (`SIGINT`/`SIGTERM`) for clean shutdown
- Main capture loop: capture → parse ethernet → branch by ethertype (ARP) or IP protocol (TCP/UDP/ICMP/DNS) → filter → output → analyze → record → stats
- Prints packet summary on exit via `stats_print_summary()`

## Data Flow (per packet)

1. `recvfrom()` → raw bytes (or read from replay file)
2. `parse_ethernet()` → EtherType check
3. Branch on EtherType:
   - `0x0806` (ARP): `parse_arp()`
   - `0x0800` (IPv4): `parse_ip()` → branch on protocol:
     - TCP (6): `parse_tcp()`, then check port 53 for DNS → `parse_dns()`
     - UDP (17): `parse_udp()`, then check port 53 for DNS → `parse_dns()`
     - ICMP (1): `parse_icmp()`
4. `filter_match()` → skip if filtered out
5. `output_packet()` → formatted output (normal/verbose/quiet/JSON + optional hex dump)
6. `analyze_packet()` → anomaly warnings (configurable) + ARP spoofing check
7. `stats_update()` → update counters and IP tracking
8. Optional: `sniffer_record_packet()` → binary log

## Binary Record Format

Each recorded packet:
```
[4 bytes: uint32_t packet_length][packet_length bytes: raw packet data]
```

Replay reads sequentially until EOF.

## Anomaly Configuration Format

`anomaly.conf` — plain text, one key=value per line:
```ini
large_packet_threshold=1500    # bytes
check_large_packet=1           # 0 to disable
check_malformed=1
check_suspicious=1
check_unknown_protocol=1
check_arp_spoofing=1
suspicious_port=23             # multiple entries allowed
suspicious_port=3389
```

Lines starting with `#` are comments. Unknown keys are ignored.

## Test Framework

`tests/test_parser.c` — standalone test binary (no external dependencies):
- Custom `ASSERT()` / `ASSERT_EQ()` / `ASSERT_STR_EQ()` macros
- 17 test functions covering all parsers, filters, anomaly config, and ARP spoofing
- Built and run via `make test`

## Security Considerations
- Requires `root` / `CAP_NET_RAW` to create raw socket
- No external input parsed beyond CLI arguments and config file (both validated)
- Record file reads are bounds-checked against `MAX_PACKET_SIZE`
- Config file parsing ignores unknown keys and validates numeric ranges
- ARP cache uses fixed-size table to prevent unbounded memory growth
