#include "filters.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

void filter_init(filter_config_t *config)
{
    config->tcp_only   = 0;
    config->udp_only   = 0;
    config->icmp_only  = 0;
    config->arp_only   = 0;
    config->port       = 0;
    config->ip_filter  = 0;
}

int filter_match(const filter_config_t *config, uint16_t ethertype,
                 const ip_header_t *ip,
                 const tcp_header_t *tcp, const udp_header_t *udp)
{
    int has_proto_filter = config->tcp_only || config->udp_only ||
                           config->icmp_only || config->arp_only;

    if (has_proto_filter) {
        if (config->arp_only && ethertype == ETH_TYPE_ARP)
            goto proto_ok;
        if (!ip)
            return 0;
        if (config->tcp_only && ip->protocol == IP_PROTO_TCP)
            goto proto_ok;
        if (config->udp_only && ip->protocol == IP_PROTO_UDP)
            goto proto_ok;
        if (config->icmp_only && ip->protocol == IP_PROTO_ICMP)
            goto proto_ok;
        return 0;
    }

proto_ok:
    /* IP filter (only applies to IP packets) */
    if (config->ip_filter != 0) {
        if (!ip)
            return 0;
        if (ip->src_ip != config->ip_filter && ip->dest_ip != config->ip_filter)
            return 0;
    }

    /* Port filter */
    if (config->port != 0) {
        if (!ip)
            return 0;
        uint16_t src_port = 0, dest_port = 0;

        if (tcp && ip->protocol == IP_PROTO_TCP) {
            src_port  = tcp->src_port;
            dest_port = tcp->dest_port;
        } else if (udp && ip->protocol == IP_PROTO_UDP) {
            src_port  = udp->src_port;
            dest_port = udp->dest_port;
        }

        if (src_port != config->port && dest_port != config->port)
            return 0;
    }

    return 1;
}

uint32_t filter_parse_ip(const char *ip_str)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "[ERROR] Invalid IP address: %s\n", ip_str);
        return 0;
    }
    return addr.s_addr;
}
