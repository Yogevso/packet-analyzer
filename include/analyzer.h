#ifndef ANALYZER_H
#define ANALYZER_H

#include <stdint.h>
#include <stddef.h>
#include "parser.h"

/* Default anomaly thresholds */
#define DEFAULT_LARGE_PACKET_THRESHOLD 1500
#define ANOMALY_MIN_PACKET_SIZE        14

/* Maximum number of configurable suspicious ports */
#define MAX_SUSPICIOUS_PORTS 32

/* ARP cache size for spoofing detection */
#define ARP_CACHE_SIZE 256

/* Configurable anomaly rules */
typedef struct {
    size_t   large_packet_threshold;
    int      check_large_packets;       /* enable/disable */
    int      check_malformed_headers;
    int      check_suspicious_ports;
    int      check_unknown_protocols;
    int      check_arp_spoofing;
    uint16_t suspicious_ports[MAX_SUSPICIOUS_PORTS];
    int      suspicious_port_count;
} anomaly_config_t;

/* Initialize anomaly config with defaults. */
void anomaly_config_init(anomaly_config_t *config);

/* Load anomaly config from file. Returns 0 on success, -1 on error. */
int anomaly_config_load(anomaly_config_t *config, const char *filepath);

/* Run all anomaly checks on a parsed packet. Returns number of anomalies found. */
int analyze_packet(const anomaly_config_t *config,
                   const uint8_t *raw, size_t raw_len,
                   const ip_header_t *ip,
                   const tcp_header_t *tcp,
                   const udp_header_t *udp);

/* Check for ARP spoofing (IP mapped to different MAC). Returns 1 if spoof detected. */
int check_arp_spoofing(const arp_header_t *arp);

/* Reset ARP spoofing cache. */
void arp_cache_reset(void);

/* Check for oversized packets. */
int check_large_packet(size_t packet_size, size_t threshold);

/* Check for malformed IP header. */
int check_malformed_ip(const ip_header_t *ip, size_t available_len);

/* Check for suspicious ports against config list. */
int check_suspicious_port(const anomaly_config_t *config,
                          uint16_t src_port, uint16_t dest_port);

/* Check for unknown/uncommon IP protocol numbers. */
int check_unknown_protocol(uint8_t protocol);

#endif /* ANALYZER_H */
