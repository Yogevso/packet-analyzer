#include "stats.h"
#include "parser.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

void stats_init(packet_stats_t *stats)
{
    memset(stats, 0, sizeof(*stats));
    stats->start_time = time(NULL);
}

static uint32_t stats_ip_hash(uint32_t ip)
{
    return (ip * 2654435761U) % STATS_IP_SLOTS;
}

static void stats_ip_inc(ip_counter_t *table, uint32_t ip)
{
    if (ip == 0)
        return;
    uint32_t idx = stats_ip_hash(ip);
    for (uint32_t i = 0; i < STATS_IP_SLOTS; i++) {
        uint32_t slot = (idx + i) % STATS_IP_SLOTS;
        if (table[slot].ip == ip || table[slot].count == 0) {
            table[slot].ip = ip;
            table[slot].count++;
            return;
        }
    }
}

void stats_update(packet_stats_t *stats, size_t pkt_len, uint8_t protocol,
                  uint32_t src_ip, uint32_t dst_ip, int is_arp, int is_dns)
{
    stats->total_packets++;
    stats->total_bytes += pkt_len;

    if (is_arp) {
        stats->arp_count++;
    } else {
        switch (protocol) {
        case IP_PROTO_TCP:  stats->tcp_count++;  break;
        case IP_PROTO_UDP:  stats->udp_count++;  break;
        case IP_PROTO_ICMP: stats->icmp_count++; break;
        default:            stats->other_count++; break;
        }
    }

    if (is_dns)
        stats->dns_count++;

    stats_ip_inc(stats->src_ips, src_ip);
    stats_ip_inc(stats->dst_ips, dst_ip);
}

void stats_add_anomaly(packet_stats_t *stats, int count)
{
    stats->anomaly_count += (uint64_t)count;
}

/* Find top-N IPs from a counter table */
static void find_top_ips(const ip_counter_t *table, ip_counter_t *top, int n)
{
    memset(top, 0, sizeof(ip_counter_t) * (size_t)n);
    for (int s = 0; s < STATS_IP_SLOTS; s++) {
        if (table[s].count == 0)
            continue;
        /* Insert into sorted top-N */
        for (int i = 0; i < n; i++) {
            if (table[s].count > top[i].count) {
                /* Shift down */
                for (int j = n - 1; j > i; j--)
                    top[j] = top[j - 1];
                top[i] = table[s];
                break;
            }
        }
    }
}

void stats_print_summary(const packet_stats_t *stats, FILE *out)
{
    time_t elapsed = time(NULL) - stats->start_time;
    if (elapsed < 1) elapsed = 1;

    fprintf(out, "\n");
    fprintf(out, "╔══════════════════════════════════════╗\n");
    fprintf(out, "║         CAPTURE SUMMARY              ║\n");
    fprintf(out, "╠══════════════════════════════════════╣\n");
    fprintf(out, "║  Duration     : %ld seconds\n", (long)elapsed);
    fprintf(out, "║  Total Packets: %lu\n", (unsigned long)stats->total_packets);
    fprintf(out, "║  Total Bytes  : %lu\n", (unsigned long)stats->total_bytes);
    fprintf(out, "║  Packets/sec  : %.1f\n", (double)stats->total_packets / (double)elapsed);
    fprintf(out, "║  Bytes/sec    : %.1f\n", (double)stats->total_bytes / (double)elapsed);
    fprintf(out, "╠══════════════════════════════════════╣\n");
    fprintf(out, "║  TCP   : %lu\n", (unsigned long)stats->tcp_count);
    fprintf(out, "║  UDP   : %lu\n", (unsigned long)stats->udp_count);
    fprintf(out, "║  ICMP  : %lu\n", (unsigned long)stats->icmp_count);
    fprintf(out, "║  ARP   : %lu\n", (unsigned long)stats->arp_count);
    fprintf(out, "║  DNS   : %lu\n", (unsigned long)stats->dns_count);
    fprintf(out, "║  Other : %lu\n", (unsigned long)stats->other_count);
    fprintf(out, "╠══════════════════════════════════════╣\n");
    fprintf(out, "║  Anomalies    : %lu\n", (unsigned long)stats->anomaly_count);
    fprintf(out, "╠══════════════════════════════════════╣\n");

    /* Top source IPs */
    ip_counter_t top_src[5];
    find_top_ips(stats->src_ips, top_src, 5);
    fprintf(out, "║  Top Source IPs:\n");
    for (int i = 0; i < 5 && top_src[i].count > 0; i++) {
        char ip_buf[16];
        ip_to_str(top_src[i].ip, ip_buf, sizeof(ip_buf));
        fprintf(out, "║    %-15s  %lu pkts\n", ip_buf, (unsigned long)top_src[i].count);
    }

    /* Top destination IPs */
    ip_counter_t top_dst[5];
    find_top_ips(stats->dst_ips, top_dst, 5);
    fprintf(out, "║  Top Destination IPs:\n");
    for (int i = 0; i < 5 && top_dst[i].count > 0; i++) {
        char ip_buf[16];
        ip_to_str(top_dst[i].ip, ip_buf, sizeof(ip_buf));
        fprintf(out, "║    %-15s  %lu pkts\n", ip_buf, (unsigned long)top_dst[i].count);
    }

    fprintf(out, "╚══════════════════════════════════════╝\n");
}

void stats_print_live(const packet_stats_t *stats)
{
    time_t elapsed = time(NULL) - stats->start_time;
    if (elapsed < 1) elapsed = 1;

    double pps = (double)stats->total_packets / (double)elapsed;
    double bps = (double)stats->total_bytes / (double)elapsed;

    /* Clear line and print live stats */
    printf("\r\033[K[LIVE] %lu pkts | %.0f pkt/s | %.0f B/s | TCP:%lu UDP:%lu ICMP:%lu ARP:%lu DNS:%lu | Anomalies:%lu",
           (unsigned long)stats->total_packets, pps, bps,
           (unsigned long)stats->tcp_count,
           (unsigned long)stats->udp_count,
           (unsigned long)stats->icmp_count,
           (unsigned long)stats->arp_count,
           (unsigned long)stats->dns_count,
           (unsigned long)stats->anomaly_count);
    fflush(stdout);
}
