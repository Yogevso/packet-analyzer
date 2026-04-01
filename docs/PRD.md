# Product Requirements Document — Packet Analyzer

## Project Name
**Packet Analyzer** (Wireshark-lite CLI)

## Objective
Build a low-level network packet analyzer that enables:
- Real-time packet capture via raw sockets
- Protocol parsing (Ethernet / IP / TCP / UDP)
- Traffic filtering by protocol, port, and IP
- Anomaly detection (oversized packets, suspicious ports, malformed headers)
- Structured, readable terminal output

## Target Users
- System engineers
- Network engineers
- QA / validation engineers
- Developers debugging network issues

## Problem Statement
Debugging network/system issues is difficult because traffic is opaque, issues happen at the packet/header level, and tools like Wireshark are heavy and complex. A lightweight, controllable, engineer-friendly tool is needed.

## Solution
A CLI-based packet analyzer that captures packets using raw sockets, parses protocol layers, allows filtering, detects anomalies, and outputs structured data.

## Core Features
1. **Packet Capture** — `AF_PACKET` raw socket, real-time, interface selection (`--iface`)
2. **Protocol Parsing** — Ethernet, IPv4, TCP, UDP, ICMP, ARP, DNS headers
3. **Filtering** — `--tcp`, `--udp`, `--icmp`, `--arp`, `--port`, `--ip`
4. **Anomaly Detection** — large packets, suspicious ports, malformed headers, unknown protocols, ARP spoofing
5. **Configurable Rules** — external config file for anomaly thresholds, toggling checks, suspicious port list
6. **Output Modes** — normal (layered), verbose (all fields), quiet (one-line), JSON (structured)
7. **Color Output** — ANSI color-coded protocol layers (`--color`)
8. **Hex Dump** — raw packet bytes in hex + ASCII (`--hex`)
9. **Live Statistics** — real-time packets/sec, bytes/sec, protocol distribution (`--stats`)
10. **Capture Summary** — per-protocol breakdown, top IPs, anomaly count on exit
11. **DNS Analysis** — query name parsing, type identification
12. **ARP Spoofing Detection** — IP-to-MAC cache with change alerts
13. **Logging** — `--log` to file
14. **Traffic Replay** — `--record` / `--replay`
15. **Unit Tests** — parser, filter, and anomaly detection tests (`make test`)

## Success Criteria
- Packets captured reliably from raw socket
- Protocol parsing produces correct header fields
- Filters correctly include/exclude packets
- Anomalies are detected and reported
- CLI is intuitive and well-documented
