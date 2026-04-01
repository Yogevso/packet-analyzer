#ifndef FILTERS_H
#define FILTERS_H

#include <stdint.h>
#include "parser.h"

typedef struct {
    int      tcp_only;       /* filter: show only TCP */
    int      udp_only;       /* filter: show only UDP */
    int      icmp_only;      /* filter: show only ICMP */
    int      arp_only;       /* filter: show only ARP */
    uint16_t port;           /* filter: specific port (0 = any) */
    uint32_t ip_filter;      /* filter: specific IP (0 = any) */
} filter_config_t;

/* Initialize filter config with defaults (no filtering). */
void filter_init(filter_config_t *config);

/* Check if a packet passes the filter. Returns 1 if it passes, 0 if it should be dropped.
   ip can be NULL for non-IP packets (e.g. ARP). ethertype is used for ARP filtering. */
int filter_match(const filter_config_t *config, uint16_t ethertype,
                 const ip_header_t *ip,
                 const tcp_header_t *tcp, const udp_header_t *udp);

/* Parse an IPv4 address string into a uint32_t in network byte order. Returns 0 on error. */
uint32_t filter_parse_ip(const char *ip_str);

#endif /* FILTERS_H */
