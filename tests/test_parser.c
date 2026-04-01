/*
 * Unit tests for the packet parser module.
 * Build: make test
 *
 * This is a minimal test framework — no external dependencies.
 * Each test constructs raw bytes and verifies parsed output.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "parser.h"
#include "filters.h"
#include "analyzer.h"

static int tests_run    = 0;
static int tests_passed = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
    } else { \
        tests_passed++; \
    } \
} while (0)

/* ── Helper: build a raw Ethernet + IP + TCP packet ── */

static size_t build_eth_ip_tcp(uint8_t *buf, size_t buf_size,
                                uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint8_t tcp_flags)
{
    (void)buf_size;
    memset(buf, 0, 54);

    /* Ethernet header (14 bytes) */
    buf[0] = 0xaa; buf[1] = 0xbb; buf[2] = 0xcc; /* dst mac */
    buf[3] = 0xdd; buf[4] = 0xee; buf[5] = 0x01;
    buf[6] = 0x11; buf[7] = 0x22; buf[8] = 0x33; /* src mac */
    buf[9] = 0x44; buf[10] = 0x55; buf[11] = 0x66;
    *(uint16_t *)(buf + 12) = htons(0x0800);       /* IPv4 */

    /* IP header (20 bytes) at offset 14 */
    buf[14] = 0x45;  /* version=4, ihl=5 */
    *(uint16_t *)(buf + 16) = htons(40);  /* total length: 20 IP + 20 TCP */
    buf[22] = 64;    /* TTL */
    buf[23] = 6;     /* TCP */
    memcpy(buf + 26, &src_ip, 4);
    memcpy(buf + 30, &dst_ip, 4);

    /* TCP header (20 bytes) at offset 34 */
    *(uint16_t *)(buf + 34) = htons(src_port);
    *(uint16_t *)(buf + 36) = htons(dst_port);
    buf[46] = 0x50;  /* data offset = 5 */
    buf[47] = tcp_flags;

    return 54;
}

static size_t build_eth_ip_udp(uint8_t *buf, size_t buf_size,
                                uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port)
{
    (void)buf_size;
    memset(buf, 0, 42);

    /* Ethernet */
    *(uint16_t *)(buf + 12) = htons(0x0800);

    /* IP */
    buf[14] = 0x45;
    *(uint16_t *)(buf + 16) = htons(28);  /* 20 IP + 8 UDP */
    buf[22] = 64;
    buf[23] = 17;  /* UDP */
    memcpy(buf + 26, &src_ip, 4);
    memcpy(buf + 30, &dst_ip, 4);

    /* UDP (8 bytes) at offset 34 */
    *(uint16_t *)(buf + 34) = htons(src_port);
    *(uint16_t *)(buf + 36) = htons(dst_port);
    *(uint16_t *)(buf + 38) = htons(8);  /* length */

    return 42;
}

static size_t build_eth_arp(uint8_t *buf, size_t buf_size,
                             uint16_t opcode,
                             const uint8_t *sender_mac, uint32_t sender_ip,
                             const uint8_t *target_mac, uint32_t target_ip)
{
    (void)buf_size;
    memset(buf, 0, 42);

    /* Ethernet */
    *(uint16_t *)(buf + 12) = htons(0x0806);

    /* ARP (28 bytes) at offset 14 */
    *(uint16_t *)(buf + 14) = htons(1);       /* HW type: Ethernet */
    *(uint16_t *)(buf + 16) = htons(0x0800);  /* Proto: IPv4 */
    buf[18] = 6;   /* HW len */
    buf[19] = 4;   /* Proto len */
    *(uint16_t *)(buf + 20) = htons(opcode);
    memcpy(buf + 22, sender_mac, 6);
    memcpy(buf + 28, &sender_ip, 4);
    memcpy(buf + 32, target_mac, 6);
    memcpy(buf + 38, &target_ip, 4);

    return 42;
}

static size_t build_eth_ip_icmp(uint8_t *buf, size_t buf_size,
                                 uint32_t src_ip, uint32_t dst_ip,
                                 uint8_t type, uint8_t code)
{
    (void)buf_size;
    memset(buf, 0, 42);

    /* Ethernet */
    *(uint16_t *)(buf + 12) = htons(0x0800);

    /* IP */
    buf[14] = 0x45;
    *(uint16_t *)(buf + 16) = htons(28);
    buf[22] = 64;
    buf[23] = 1;  /* ICMP */
    memcpy(buf + 26, &src_ip, 4);
    memcpy(buf + 30, &dst_ip, 4);

    /* ICMP (8 bytes) at offset 34 */
    buf[34] = type;
    buf[35] = code;
    *(uint16_t *)(buf + 38) = htons(0x1234);  /* identifier */
    *(uint16_t *)(buf + 40) = htons(1);        /* sequence */

    return 42;
}

/* ═════════════════════════════════════ */
/*            TEST FUNCTIONS             */
/* ═════════════════════════════════════ */

static void test_parse_ethernet(void)
{
    printf("test_parse_ethernet...\n");
    uint8_t buf[64];
    build_eth_ip_tcp(buf, sizeof(buf), 0, 0, 0, 0, 0);

    eth_header_t eth;
    int rc = parse_ethernet(buf, 54, &eth);
    ASSERT(rc == 0, "should parse OK");
    ASSERT(eth.ethertype == 0x0800, "ethertype should be IPv4");
    ASSERT(eth.src_mac[0] == 0x11, "src mac byte 0");

    /* Too short */
    rc = parse_ethernet(buf, 10, &eth);
    ASSERT(rc == -1, "should fail on short packet");

    /* NULL */
    rc = parse_ethernet(NULL, 54, &eth);
    ASSERT(rc == -1, "should fail on NULL");
}

static void test_parse_ip(void)
{
    printf("test_parse_ip...\n");
    uint8_t buf[64];
    uint32_t src = htonl(0xC0A80102);  /* 192.168.1.2 */
    uint32_t dst = htonl(0x08080808);  /* 8.8.8.8 */
    build_eth_ip_tcp(buf, sizeof(buf), src, dst, 1234, 80, TCP_FLAG_SYN);

    ip_header_t ip;
    int rc = parse_ip(buf + ETH_HEADER_LEN, 40, &ip);
    ASSERT(rc == 0, "should parse OK");
    ASSERT(ip.version == 4, "version should be 4");
    ASSERT(ip.ihl == 5, "IHL should be 5");
    ASSERT(ip.protocol == IP_PROTO_TCP, "protocol should be TCP");
    ASSERT(ip.ttl == 64, "TTL should be 64");
    ASSERT(ip.src_ip == src, "src IP mismatch");
    ASSERT(ip.dest_ip == dst, "dst IP mismatch");

    /* Too short */
    rc = parse_ip(buf + ETH_HEADER_LEN, 10, &ip);
    ASSERT(rc == -1, "should fail on short data");
}

static void test_parse_tcp(void)
{
    printf("test_parse_tcp...\n");
    uint8_t buf[64];
    build_eth_ip_tcp(buf, sizeof(buf), 0, 0, 52344, 443, TCP_FLAG_SYN | TCP_FLAG_ACK);

    tcp_header_t tcp;
    int rc = parse_tcp(buf + ETH_HEADER_LEN + 20, 20, &tcp);
    ASSERT(rc == 0, "should parse OK");
    ASSERT(tcp.src_port == 52344, "src port");
    ASSERT(tcp.dest_port == 443, "dst port");
    ASSERT((tcp.flags & TCP_FLAG_SYN), "SYN flag set");
    ASSERT((tcp.flags & TCP_FLAG_ACK), "ACK flag set");
    ASSERT(!(tcp.flags & TCP_FLAG_FIN), "FIN flag not set");
}

static void test_parse_udp(void)
{
    printf("test_parse_udp...\n");
    uint8_t buf[64];
    build_eth_ip_udp(buf, sizeof(buf), 0, 0, 12345, 53);

    udp_header_t udp;
    int rc = parse_udp(buf + ETH_HEADER_LEN + 20, 8, &udp);
    ASSERT(rc == 0, "should parse OK");
    ASSERT(udp.src_port == 12345, "src port");
    ASSERT(udp.dest_port == 53, "dst port");
    ASSERT(udp.length == 8, "length");
}

static void test_parse_icmp(void)
{
    printf("test_parse_icmp...\n");
    uint8_t buf[64];
    uint32_t src = htonl(0x0A000001);
    uint32_t dst = htonl(0x0A000002);
    build_eth_ip_icmp(buf, sizeof(buf), src, dst, ICMP_TYPE_ECHO_REQUEST, 0);

    icmp_header_t icmp;
    int rc = parse_icmp(buf + ETH_HEADER_LEN + 20, 8, &icmp);
    ASSERT(rc == 0, "should parse OK");
    ASSERT(icmp.type == ICMP_TYPE_ECHO_REQUEST, "type should be echo request");
    ASSERT(icmp.code == 0, "code should be 0");
    ASSERT(icmp.identifier == 0x1234, "identifier");
    ASSERT(icmp.sequence == 1, "sequence");
}

static void test_parse_arp(void)
{
    printf("test_parse_arp...\n");
    uint8_t sender_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint8_t target_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint32_t sender_ip = htonl(0xC0A80101);  /* 192.168.1.1 */
    uint32_t target_ip = htonl(0xC0A80102);  /* 192.168.1.2 */

    uint8_t buf[64];
    build_eth_arp(buf, sizeof(buf), ARP_OP_REQUEST, sender_mac, sender_ip, target_mac, target_ip);

    arp_header_t arp;
    int rc = parse_arp(buf + ETH_HEADER_LEN, 28, &arp);
    ASSERT(rc == 0, "should parse OK");
    ASSERT(arp.opcode == ARP_OP_REQUEST, "opcode should be request");
    ASSERT(arp.sender_ip == sender_ip, "sender IP");
    ASSERT(arp.target_ip == target_ip, "target IP");
    ASSERT(memcmp(arp.sender_mac, sender_mac, 6) == 0, "sender MAC");
}

static void test_parse_dns(void)
{
    printf("test_parse_dns...\n");
    /* Build a minimal DNS query for "example.com" type A */
    uint8_t dns_pkt[64];
    memset(dns_pkt, 0, sizeof(dns_pkt));

    /* DNS header (12 bytes) */
    *(uint16_t *)(dns_pkt + 0) = htons(0xABCD);  /* ID */
    *(uint16_t *)(dns_pkt + 2) = htons(0x0100);  /* flags: standard query */
    *(uint16_t *)(dns_pkt + 4) = htons(1);        /* QD count */

    /* Query: example.com */
    uint8_t *q = dns_pkt + 12;
    *q++ = 7;  /* "example" */
    memcpy(q, "example", 7); q += 7;
    *q++ = 3;  /* "com" */
    memcpy(q, "com", 3); q += 3;
    *q++ = 0;  /* null terminator */
    *(uint16_t *)q = htons(1);  /* QTYPE: A */
    q += 2;
    *(uint16_t *)q = htons(1);  /* QCLASS: IN */
    q += 2;

    size_t dns_len = (size_t)(q - dns_pkt);

    dns_header_t dns;
    int rc = parse_dns(dns_pkt, dns_len, &dns);
    ASSERT(rc == 0, "should parse OK");
    ASSERT(dns.id == 0xABCD, "id");
    ASSERT(dns.qd_count == 1, "qd_count");
    ASSERT(dns.is_response == 0, "should be query");
    ASSERT(strcmp(dns.query_name, "example.com") == 0, "query name");
    ASSERT(dns.query_type == 1, "query type A");
}

static void test_ip_to_str(void)
{
    printf("test_ip_to_str...\n");
    char buf[16];
    uint32_t ip = htonl(0xC0A80101);  /* 192.168.1.1 */
    ip_to_str(ip, buf, sizeof(buf));
    ASSERT(strcmp(buf, "192.168.1.1") == 0, "ip string");
}

static void test_tcp_flags_to_str(void)
{
    printf("test_tcp_flags_to_str...\n");
    char buf[32];

    tcp_flags_to_str(TCP_FLAG_SYN, buf, sizeof(buf));
    ASSERT(strcmp(buf, "SYN") == 0, "SYN only");

    tcp_flags_to_str(TCP_FLAG_SYN | TCP_FLAG_ACK, buf, sizeof(buf));
    ASSERT(strstr(buf, "SYN") != NULL, "has SYN");
    ASSERT(strstr(buf, "ACK") != NULL, "has ACK");
}

static void test_mac_to_str(void)
{
    printf("test_mac_to_str...\n");
    uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    char buf[18];
    mac_to_str(mac, buf, sizeof(buf));
    ASSERT(strcmp(buf, "aa:bb:cc:dd:ee:ff") == 0, "mac string");
}

static void test_protocol_name(void)
{
    printf("test_protocol_name...\n");
    ASSERT(strcmp(protocol_name(IP_PROTO_TCP), "TCP") == 0, "TCP name");
    ASSERT(strcmp(protocol_name(IP_PROTO_UDP), "UDP") == 0, "UDP name");
    ASSERT(strcmp(protocol_name(IP_PROTO_ICMP), "ICMP") == 0, "ICMP name");
    ASSERT(strcmp(protocol_name(99), "UNKNOWN") == 0, "unknown proto");
}

static void test_icmp_type_name(void)
{
    printf("test_icmp_type_name...\n");
    ASSERT(strcmp(icmp_type_name(ICMP_TYPE_ECHO_REQUEST), "Echo Request") == 0, "echo req");
    ASSERT(strcmp(icmp_type_name(ICMP_TYPE_ECHO_REPLY), "Echo Reply") == 0, "echo reply");
    ASSERT(strcmp(icmp_type_name(ICMP_TYPE_DEST_UNREACH), "Destination Unreachable") == 0, "dest unreach");
}

static void test_filter_match(void)
{
    printf("test_filter_match...\n");

    filter_config_t cfg;
    filter_init(&cfg);

    uint32_t src = htonl(0xC0A80101);
    uint32_t dst = htonl(0x08080808);

    ip_header_t ip = { .version = 4, .ihl = 5, .protocol = IP_PROTO_TCP,
                        .src_ip = src, .dest_ip = dst };
    tcp_header_t tcp = { .src_port = 12345, .dest_port = 443 };

    /* No filter — should pass */
    ASSERT(filter_match(&cfg, ETH_TYPE_IP, &ip, &tcp, NULL) == 1, "no filter passes");

    /* TCP only — should pass */
    cfg.tcp_only = 1;
    ASSERT(filter_match(&cfg, ETH_TYPE_IP, &ip, &tcp, NULL) == 1, "tcp filter passes tcp");

    /* TCP only but packet is UDP */
    ip.protocol = IP_PROTO_UDP;
    ASSERT(filter_match(&cfg, ETH_TYPE_IP, &ip, NULL, NULL) == 0, "tcp filter blocks udp");
    ip.protocol = IP_PROTO_TCP;
    cfg.tcp_only = 0;

    /* Port filter */
    cfg.port = 443;
    ASSERT(filter_match(&cfg, ETH_TYPE_IP, &ip, &tcp, NULL) == 1, "port 443 match");
    cfg.port = 80;
    ASSERT(filter_match(&cfg, ETH_TYPE_IP, &ip, &tcp, NULL) == 0, "port 80 no match");
    cfg.port = 0;

    /* IP filter */
    cfg.ip_filter = src;
    ASSERT(filter_match(&cfg, ETH_TYPE_IP, &ip, &tcp, NULL) == 1, "ip filter src match");
    cfg.ip_filter = htonl(0x01020304);
    ASSERT(filter_match(&cfg, ETH_TYPE_IP, &ip, &tcp, NULL) == 0, "ip filter no match");
    cfg.ip_filter = 0;

    /* ARP filter */
    cfg.arp_only = 1;
    ASSERT(filter_match(&cfg, ETH_TYPE_ARP, NULL, NULL, NULL) == 1, "arp filter passes arp");
    ASSERT(filter_match(&cfg, ETH_TYPE_IP, &ip, &tcp, NULL) == 0, "arp filter blocks ip");
}

static void test_anomaly_config(void)
{
    printf("test_anomaly_config...\n");

    anomaly_config_t cfg;
    anomaly_config_init(&cfg);

    ASSERT(cfg.large_packet_threshold == DEFAULT_LARGE_PACKET_THRESHOLD, "default threshold");
    ASSERT(cfg.check_large_packets == 1, "large packets enabled");
    ASSERT(cfg.suspicious_port_count == 3, "3 default suspicious ports");
}

static void test_check_large_packet(void)
{
    printf("test_check_large_packet...\n");
    ASSERT(check_large_packet(1000, 1500) == 0, "1000 < 1500 no anomaly");
    ASSERT(check_large_packet(2000, 1500) == 1, "2000 > 1500 anomaly");
}

static void test_check_unknown_protocol(void)
{
    printf("test_check_unknown_protocol...\n");
    ASSERT(check_unknown_protocol(IP_PROTO_TCP) == 0, "TCP known");
    ASSERT(check_unknown_protocol(IP_PROTO_UDP) == 0, "UDP known");
    ASSERT(check_unknown_protocol(IP_PROTO_ICMP) == 0, "ICMP known");
    ASSERT(check_unknown_protocol(47) == 1, "proto 47 unknown");
}

static void test_arp_spoofing(void)
{
    printf("test_arp_spoofing...\n");

    arp_cache_reset();

    /* First ARP reply — should be clean */
    arp_header_t arp1 = {
        .opcode = ARP_OP_REPLY,
        .sender_ip = htonl(0xC0A80101),
        .sender_mac = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
    };
    ASSERT(check_arp_spoofing(&arp1) == 0, "first reply no spoof");

    /* Same IP, same MAC — still clean */
    ASSERT(check_arp_spoofing(&arp1) == 0, "same mac no spoof");

    /* Same IP, different MAC — spoofing! */
    arp_header_t arp2 = arp1;
    arp2.sender_mac[5] = 0x02;
    ASSERT(check_arp_spoofing(&arp2) == 1, "different mac = spoof");

    /* ARP request should not trigger */
    arp_header_t arp_req = arp1;
    arp_req.opcode = ARP_OP_REQUEST;
    ASSERT(check_arp_spoofing(&arp_req) == 0, "request not checked");

    arp_cache_reset();
}

/* ═════════════════════════════════════ */
/*                MAIN                   */
/* ═════════════════════════════════════ */

int main(void)
{
    printf("\n=== Packet Analyzer Unit Tests ===\n\n");

    test_parse_ethernet();
    test_parse_ip();
    test_parse_tcp();
    test_parse_udp();
    test_parse_icmp();
    test_parse_arp();
    test_parse_dns();
    test_ip_to_str();
    test_tcp_flags_to_str();
    test_mac_to_str();
    test_protocol_name();
    test_icmp_type_name();
    test_filter_match();
    test_anomaly_config();
    test_check_large_packet();
    test_check_unknown_protocol();
    test_arp_spoofing();

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
