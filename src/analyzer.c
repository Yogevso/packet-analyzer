#include "analyzer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── Default suspicious ports ── */
static const uint16_t default_suspicious_ports[] = { 23, 21, 513 };
static const int default_suspicious_count = 3;

/* ── ARP spoofing cache ── */
typedef struct {
    uint32_t ip;
    uint8_t  mac[6];
    int      used;
} arp_entry_t;

static arp_entry_t arp_cache[ARP_CACHE_SIZE];

void arp_cache_reset(void)
{
    memset(arp_cache, 0, sizeof(arp_cache));
}

static uint32_t ip_hash(uint32_t ip)
{
    return (ip * 2654435761U) % ARP_CACHE_SIZE;
}

int check_arp_spoofing(const arp_header_t *arp)
{
    if (!arp || arp->opcode != ARP_OP_REPLY)
        return 0;

    uint32_t idx = ip_hash(arp->sender_ip);

    /* Linear probe */
    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++) {
        uint32_t slot = (idx + i) % ARP_CACHE_SIZE;
        arp_entry_t *e = &arp_cache[slot];

        if (!e->used) {
            /* New entry */
            e->ip = arp->sender_ip;
            memcpy(e->mac, arp->sender_mac, 6);
            e->used = 1;
            return 0;
        }

        if (e->ip == arp->sender_ip) {
            /* Check if MAC changed */
            if (memcmp(e->mac, arp->sender_mac, 6) != 0) {
                char ip_buf[16], old_mac[18], new_mac[18];
                ip_to_str(arp->sender_ip, ip_buf, sizeof(ip_buf));
                mac_to_str(e->mac, old_mac, sizeof(old_mac));
                mac_to_str(arp->sender_mac, new_mac, sizeof(new_mac));
                fprintf(stderr, "[ALERT] ARP spoofing detected! IP %s changed from %s to %s\n",
                        ip_buf, old_mac, new_mac);
                /* Update cache with new MAC */
                memcpy(e->mac, arp->sender_mac, 6);
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

/* ── Config management ── */

void anomaly_config_init(anomaly_config_t *config)
{
    config->large_packet_threshold = DEFAULT_LARGE_PACKET_THRESHOLD;
    config->check_large_packets    = 1;
    config->check_malformed_headers = 1;
    config->check_suspicious_ports  = 1;
    config->check_unknown_protocols = 1;
    config->check_arp_spoofing      = 1;

    /* Load default suspicious ports */
    config->suspicious_port_count = default_suspicious_count;
    for (int i = 0; i < default_suspicious_count; i++)
        config->suspicious_ports[i] = default_suspicious_ports[i];
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

int anomaly_config_load(anomaly_config_t *config, const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) {
        perror("[ERROR] Failed to open anomaly config file");
        return -1;
    }

    char line[256];
    config->suspicious_port_count = 0;

    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if (s[0] == '#' || s[0] == '\0')
            continue;

        char key[64], value[128];
        if (sscanf(s, "%63[^=]=%127s", key, value) != 2)
            continue;

        char *k = trim(key);
        char *v = trim(value);

        if (strcmp(k, "large_packet_threshold") == 0) {
            config->large_packet_threshold = (size_t)strtoul(v, NULL, 10);
        } else if (strcmp(k, "check_large_packets") == 0) {
            config->check_large_packets = atoi(v);
        } else if (strcmp(k, "check_malformed_headers") == 0) {
            config->check_malformed_headers = atoi(v);
        } else if (strcmp(k, "check_suspicious_ports") == 0) {
            config->check_suspicious_ports = atoi(v);
        } else if (strcmp(k, "check_unknown_protocols") == 0) {
            config->check_unknown_protocols = atoi(v);
        } else if (strcmp(k, "check_arp_spoofing") == 0) {
            config->check_arp_spoofing = atoi(v);
        } else if (strcmp(k, "suspicious_port") == 0) {
            if (config->suspicious_port_count < MAX_SUSPICIOUS_PORTS) {
                long p = strtol(v, NULL, 10);
                if (p > 0 && p <= 65535)
                    config->suspicious_ports[config->suspicious_port_count++] = (uint16_t)p;
            }
        }
    }

    fclose(f);
    return 0;
}

/* ── Individual checks ── */

int check_large_packet(size_t packet_size, size_t threshold)
{
    if (packet_size > threshold) {
        fprintf(stderr, "[WARNING] Large packet detected (%zu bytes, threshold %zu)\n",
                packet_size, threshold);
        return 1;
    }
    return 0;
}

int check_malformed_ip(const ip_header_t *ip, size_t available_len)
{
    int anomalies = 0;
    if (!ip)
        return 0;

    if (ip->ihl < 5) {
        fprintf(stderr, "[WARNING] Malformed IP header: IHL=%u (minimum is 5)\n", ip->ihl);
        anomalies++;
    }

    size_t ip_hdr_bytes = (size_t)ip->ihl * 4;
    if (ip_hdr_bytes > available_len) {
        fprintf(stderr, "[WARNING] Malformed IP header: declared length %zu exceeds available data %zu\n",
                ip_hdr_bytes, available_len);
        anomalies++;
    }

    if (ip->total_length < ip_hdr_bytes) {
        fprintf(stderr, "[WARNING] Malformed IP: total_length (%u) < header length (%zu)\n",
                ip->total_length, ip_hdr_bytes);
        anomalies++;
    }

    return anomalies;
}

int check_suspicious_port(const anomaly_config_t *config,
                          uint16_t src_port, uint16_t dest_port)
{
    int anomalies = 0;
    for (int i = 0; i < config->suspicious_port_count; i++) {
        uint16_t sp = config->suspicious_ports[i];
        if (src_port == sp) {
            fprintf(stderr, "[WARNING] Suspicious source port: %u\n", src_port);
            anomalies++;
        }
        if (dest_port == sp) {
            fprintf(stderr, "[WARNING] Suspicious destination port: %u\n", dest_port);
            anomalies++;
        }
    }
    return anomalies;
}

int check_unknown_protocol(uint8_t protocol)
{
    if (protocol != IP_PROTO_ICMP &&
        protocol != IP_PROTO_TCP  &&
        protocol != IP_PROTO_UDP) {
        fprintf(stderr, "[WARNING] Unknown/uncommon IP protocol: %u\n", protocol);
        return 1;
    }
    return 0;
}

/* ── Main analysis entry point ── */

int analyze_packet(const anomaly_config_t *config,
                   const uint8_t *raw, size_t raw_len,
                   const ip_header_t *ip,
                   const tcp_header_t *tcp,
                   const udp_header_t *udp)
{
    (void)raw;
    int anomalies = 0;

    if (config->check_large_packets)
        anomalies += check_large_packet(raw_len, config->large_packet_threshold);

    if (!ip)
        return anomalies;

    if (config->check_malformed_headers) {
        size_t ip_data_len = raw_len > ETH_HEADER_LEN ? raw_len - ETH_HEADER_LEN : 0;
        anomalies += check_malformed_ip(ip, ip_data_len);
    }

    if (config->check_unknown_protocols)
        anomalies += check_unknown_protocol(ip->protocol);

    if (config->check_suspicious_ports) {
        if (tcp)
            anomalies += check_suspicious_port(config, tcp->src_port, tcp->dest_port);
        if (udp)
            anomalies += check_suspicious_port(config, udp->src_port, udp->dest_port);
    }

    return anomalies;
}
