# Debugging Case Study — Packet Analyzer

## Scenario: Identifying Unexpected Telnet Traffic

### Problem
A server was observed making outbound connections on port 23 (Telnet), which should not occur in a production environment. Standard monitoring did not flag the traffic because it was low-volume.

### Using the Packet Analyzer

**Step 1: Capture with port filter**
```bash
sudo ./sniffer --port 23 --log telnet_traffic.log
```

**Step 2: Observe output**
```
──────────────────────────────────────
[ETH] aa:bb:cc:dd:ee:01 → ff:ee:dd:cc:bb:02 | Type: 0x0800
[IP]  10.0.0.5 → 192.168.1.100 | Proto: TCP | TTL: 64
[TCP] 48234 → 23 | Flags: SYN | Seq: 123456
Size: 74 bytes
[WARNING] Suspicious destination port: 23
```

**Step 3: Record for later analysis**
```bash
sudo ./sniffer --port 23 --record evidence.bin
```

**Step 4: Replay offline**
```bash
./sniffer --replay evidence.bin
```

### Outcome
- Identified the source process by correlating source port with `ss -tnp`
- Found a misconfigured legacy script initiating Telnet connections
- Replaced with SSH, re-verified with the analyzer

### Key Takeaways
- The `--port` filter isolated relevant traffic instantly
- Anomaly detection flagged the suspicious port automatically
- Recording + replay enabled offline forensic review
