#include "parser.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int parse_ethernet(const uint8_t *packet, size_t len, eth_header_t *eth)
{
    if (!packet || !eth || len < ETH_HEADER_LEN)
        return -1;

    memcpy(eth->dest_mac, packet, 6);
    memcpy(eth->src_mac, packet + 6, 6);
    eth->ethertype = ntohs(*(uint16_t *)(packet + 12));

    return 0;
}

int parse_ip(const uint8_t *packet, size_t len, ip_header_t *ip)
{
    if (!packet || !ip || len < 20)
        return -1;

    ip->version        = (packet[0] >> 4) & 0x0F;
    ip->ihl            = packet[0] & 0x0F;
    ip->tos            = packet[1];
    ip->total_length   = ntohs(*(uint16_t *)(packet + 2));
    ip->identification = ntohs(*(uint16_t *)(packet + 4));
    ip->flags_fragment = ntohs(*(uint16_t *)(packet + 6));
    ip->ttl            = packet[8];
    ip->protocol       = packet[9];
    ip->checksum       = ntohs(*(uint16_t *)(packet + 10));

    memcpy(&ip->src_ip, packet + 12, 4);
    memcpy(&ip->dest_ip, packet + 16, 4);

    if (ip->version != 4)
        return -1;
    if (ip->ihl < 5)
        return -1;

    return 0;
}

int parse_tcp(const uint8_t *packet, size_t len, tcp_header_t *tcp)
{
    if (!packet || !tcp || len < 20)
        return -1;

    tcp->src_port    = ntohs(*(uint16_t *)(packet));
    tcp->dest_port   = ntohs(*(uint16_t *)(packet + 2));
    tcp->seq_num     = ntohl(*(uint32_t *)(packet + 4));
    tcp->ack_num     = ntohl(*(uint32_t *)(packet + 8));
    tcp->data_offset = (packet[12] >> 4) & 0x0F;
    tcp->flags       = packet[13];
    tcp->window      = ntohs(*(uint16_t *)(packet + 14));
    tcp->checksum    = ntohs(*(uint16_t *)(packet + 16));
    tcp->urgent_ptr  = ntohs(*(uint16_t *)(packet + 18));

    return 0;
}

int parse_udp(const uint8_t *packet, size_t len, udp_header_t *udp)
{
    if (!packet || !udp || len < 8)
        return -1;

    udp->src_port  = ntohs(*(uint16_t *)(packet));
    udp->dest_port = ntohs(*(uint16_t *)(packet + 2));
    udp->length    = ntohs(*(uint16_t *)(packet + 4));
    udp->checksum  = ntohs(*(uint16_t *)(packet + 6));

    return 0;
}

int parse_icmp(const uint8_t *packet, size_t len, icmp_header_t *icmp)
{
    if (!packet || !icmp || len < 8)
        return -1;

    icmp->type       = packet[0];
    icmp->code       = packet[1];
    icmp->checksum   = ntohs(*(uint16_t *)(packet + 2));
    icmp->identifier = ntohs(*(uint16_t *)(packet + 4));
    icmp->sequence   = ntohs(*(uint16_t *)(packet + 6));

    return 0;
}

int parse_arp(const uint8_t *packet, size_t len, arp_header_t *arp)
{
    if (!packet || !arp || len < 28)
        return -1;

    arp->hw_type    = ntohs(*(uint16_t *)(packet));
    arp->proto_type = ntohs(*(uint16_t *)(packet + 2));
    arp->hw_len     = packet[4];
    arp->proto_len  = packet[5];
    arp->opcode     = ntohs(*(uint16_t *)(packet + 6));

    /* Standard Ethernet/IPv4 ARP: hw_len=6, proto_len=4 */
    if (arp->hw_len != 6 || arp->proto_len != 4)
        return -1;

    memcpy(arp->sender_mac, packet + 8, 6);
    memcpy(&arp->sender_ip, packet + 14, 4);
    memcpy(arp->target_mac, packet + 18, 6);
    memcpy(&arp->target_ip, packet + 24, 4);

    return 0;
}

int parse_dns(const uint8_t *packet, size_t len, dns_header_t *dns)
{
    if (!packet || !dns || len < 12)
        return -1;

    dns->id          = ntohs(*(uint16_t *)(packet));
    dns->flags       = ntohs(*(uint16_t *)(packet + 2));
    dns->qd_count    = ntohs(*(uint16_t *)(packet + 4));
    dns->an_count    = ntohs(*(uint16_t *)(packet + 6));
    dns->ns_count    = ntohs(*(uint16_t *)(packet + 8));
    dns->ar_count    = ntohs(*(uint16_t *)(packet + 10));
    dns->is_response = (dns->flags >> 15) & 1;
    dns->query_name[0] = '\0';
    dns->query_type    = 0;

    /* Decode first query name if present */
    if (dns->qd_count == 0 || len <= 12)
        return 0;

    const uint8_t *p = packet + 12;
    const uint8_t *end = packet + len;
    size_t name_pos = 0;

    while (p < end && *p != 0) {
        uint8_t label_len = *p++;
        if (label_len > 63 || p + label_len > end)
            break;
        if (name_pos > 0 && name_pos < sizeof(dns->query_name) - 1)
            dns->query_name[name_pos++] = '.';
        for (uint8_t j = 0; j < label_len && name_pos < sizeof(dns->query_name) - 1; j++)
            dns->query_name[name_pos++] = (char)*p++;
    }
    dns->query_name[name_pos] = '\0';

    /* Skip null terminator + read QTYPE */
    if (p < end)
        p++; /* null terminator */
    if (p + 2 <= end)
        dns->query_type = ntohs(*(uint16_t *)p);

    return 0;
}

void ip_to_str(uint32_t ip, char *buf, size_t buf_size)
{
    uint8_t *bytes = (uint8_t *)&ip;
    snprintf(buf, buf_size, "%u.%u.%u.%u",
             bytes[0], bytes[1], bytes[2], bytes[3]);
}

void tcp_flags_to_str(uint8_t flags, char *buf, size_t buf_size)
{
    buf[0] = '\0';
    size_t pos = 0;

    struct { uint8_t mask; const char *name; } flag_map[] = {
        { TCP_FLAG_SYN, "SYN" },
        { TCP_FLAG_ACK, "ACK" },
        { TCP_FLAG_FIN, "FIN" },
        { TCP_FLAG_RST, "RST" },
        { TCP_FLAG_PSH, "PSH" },
        { TCP_FLAG_URG, "URG" },
    };

    for (size_t i = 0; i < sizeof(flag_map) / sizeof(flag_map[0]); i++) {
        if (flags & flag_map[i].mask) {
            if (pos > 0 && pos < buf_size - 1) {
                buf[pos++] = ' ';
            }
            size_t name_len = strlen(flag_map[i].name);
            if (pos + name_len < buf_size) {
                memcpy(buf + pos, flag_map[i].name, name_len);
                pos += name_len;
            }
        }
    }
    buf[pos] = '\0';
}

void mac_to_str(const uint8_t *mac, char *buf, size_t buf_size)
{
    snprintf(buf, buf_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char *protocol_name(uint8_t proto)
{
    switch (proto) {
    case IP_PROTO_ICMP: return "ICMP";
    case IP_PROTO_TCP:  return "TCP";
    case IP_PROTO_UDP:  return "UDP";
    default:            return "UNKNOWN";
    }
}

const char *icmp_type_name(uint8_t type)
{
    switch (type) {
    case ICMP_TYPE_ECHO_REPLY:   return "Echo Reply";
    case ICMP_TYPE_DEST_UNREACH: return "Destination Unreachable";
    case ICMP_TYPE_REDIRECT:     return "Redirect";
    case ICMP_TYPE_ECHO_REQUEST: return "Echo Request";
    case ICMP_TYPE_TIME_EXCEED:  return "Time Exceeded";
    default:                     return "Other";
    }
}

const char *arp_opcode_name(uint16_t opcode)
{
    switch (opcode) {
    case ARP_OP_REQUEST: return "Request";
    case ARP_OP_REPLY:   return "Reply";
    default:             return "Unknown";
    }
}

const char *dns_type_name(uint16_t qtype)
{
    switch (qtype) {
    case 1:   return "A";
    case 2:   return "NS";
    case 5:   return "CNAME";
    case 6:   return "SOA";
    case 15:  return "MX";
    case 16:  return "TXT";
    case 28:  return "AAAA";
    case 33:  return "SRV";
    case 255: return "ANY";
    default:  return "OTHER";
    }
}
