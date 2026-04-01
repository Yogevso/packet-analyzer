#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <stddef.h>

/* Ethernet header: 14 bytes */
#define ETH_HEADER_LEN 14
#define ETH_TYPE_IP    0x0800
#define ETH_TYPE_ARP   0x0806
#define ETH_TYPE_IPV6  0x86DD

/* IP protocols */
#define IP_PROTO_ICMP  1
#define IP_PROTO_TCP   6
#define IP_PROTO_UDP   17

/* TCP flags */
#define TCP_FLAG_FIN   0x01
#define TCP_FLAG_SYN   0x02
#define TCP_FLAG_RST   0x04
#define TCP_FLAG_PSH   0x08
#define TCP_FLAG_ACK   0x10
#define TCP_FLAG_URG   0x20

/* ARP opcodes */
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

/* DNS port */
#define DNS_PORT 53

/* ICMP types */
#define ICMP_TYPE_ECHO_REPLY   0
#define ICMP_TYPE_DEST_UNREACH 3
#define ICMP_TYPE_REDIRECT     5
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEED  11

typedef struct {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} eth_header_t;

typedef struct {
    uint8_t  version;
    uint8_t  ihl;           /* header length in 32-bit words */
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} ip_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;   /* header length in 32-bit words */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} icmp_header_t;

typedef struct {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint32_t sender_ip;
    uint8_t  target_mac[6];
    uint32_t target_ip;
} arp_header_t;

/* DNS header (12 bytes) + first query name */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
    char     query_name[256]; /* decoded first query name */
    uint16_t query_type;
    int      is_response;
} dns_header_t;

/* Parse Ethernet header from raw packet. Returns 0 on success, -1 on error. */
int parse_ethernet(const uint8_t *packet, size_t len, eth_header_t *eth);

/* Parse IP header from raw packet (after Ethernet). Returns 0 on success, -1 on error. */
int parse_ip(const uint8_t *packet, size_t len, ip_header_t *ip);

/* Parse TCP header. packet should point to start of TCP header. */
int parse_tcp(const uint8_t *packet, size_t len, tcp_header_t *tcp);

/* Parse UDP header. packet should point to start of UDP header. */
int parse_udp(const uint8_t *packet, size_t len, udp_header_t *udp);

/* Parse ICMP header. packet should point to start of ICMP header. */
int parse_icmp(const uint8_t *packet, size_t len, icmp_header_t *icmp);

/* Parse ARP header. packet should point to start of ARP payload (after Ethernet). */
int parse_arp(const uint8_t *packet, size_t len, arp_header_t *arp);

/* Parse DNS header + first query name from UDP payload. */
int parse_dns(const uint8_t *packet, size_t len, dns_header_t *dns);

/* Convert IPv4 address to string. buf must be at least 16 bytes. */
void ip_to_str(uint32_t ip, char *buf, size_t buf_size);

/* Format TCP flags into a human-readable string. buf must be at least 32 bytes. */
void tcp_flags_to_str(uint8_t flags, char *buf, size_t buf_size);

/* Format MAC address into string. buf must be at least 18 bytes. */
void mac_to_str(const uint8_t *mac, char *buf, size_t buf_size);

/* Return protocol name string for IP protocol number. */
const char *protocol_name(uint8_t proto);

/* Return ICMP type name. */
const char *icmp_type_name(uint8_t type);

/* Return ARP opcode name. */
const char *arp_opcode_name(uint16_t opcode);

/* Return DNS query type name. */
const char *dns_type_name(uint16_t qtype);

#endif /* PARSER_H */
