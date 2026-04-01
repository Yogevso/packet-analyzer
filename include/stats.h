#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* Top-N IPs to track */
#define STATS_TOP_IPS 10
#define STATS_IP_SLOTS 512

typedef struct {
    uint32_t ip;
    uint64_t count;
} ip_counter_t;

typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_count;
    uint64_t udp_count;
    uint64_t icmp_count;
    uint64_t arp_count;
    uint64_t dns_count;
    uint64_t other_count;
    uint64_t anomaly_count;
    time_t   start_time;

    /* IP tracking (simple hash table) */
    ip_counter_t src_ips[STATS_IP_SLOTS];
    ip_counter_t dst_ips[STATS_IP_SLOTS];
} packet_stats_t;

/* Initialize stats. */
void stats_init(packet_stats_t *stats);

/* Update stats with a new packet. protocol=0 means non-IP (ARP etc). */
void stats_update(packet_stats_t *stats, size_t pkt_len, uint8_t protocol,
                  uint32_t src_ip, uint32_t dst_ip, int is_arp, int is_dns);

/* Increment anomaly counter. */
void stats_add_anomaly(packet_stats_t *stats, int count);

/* Print final summary to a FILE*. */
void stats_print_summary(const packet_stats_t *stats, FILE *out);

/* Print live stats line (single line, updated in place). */
void stats_print_live(const packet_stats_t *stats);

#endif /* STATS_H */
