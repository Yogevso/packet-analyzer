#include "output.h"
#include "parser.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

void output_init(output_config_t *config)
{
    config->mode     = OUTPUT_MODE_NORMAL;
    config->color    = 0;
    config->hex_dump = 0;
    config->logfile  = NULL;
}

/* Helper: print to both stdout and logfile (log never gets color) */
static void emit(const output_config_t *config, const char *color,
                 const char *fmt, ...)
{
    va_list args;
    char buf[1024];

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (config->color && color)
        printf("%s%s%s", color, buf, COLOR_RESET);
    else
        printf("%s", buf);

    if (config->logfile)
        fprintf(config->logfile, "%s", buf);
}

/* ── JSON output ── */

static void output_json(const output_config_t *config, int packet_num,
                        size_t raw_len,
                        const eth_header_t *eth,
                        const ip_header_t *ip,
                        const tcp_header_t *tcp,
                        const udp_header_t *udp,
                        const icmp_header_t *icmp,
                        const arp_header_t *arp,
                        const dns_header_t *dns)
{
    char src_mac[18], dest_mac[18];
    mac_to_str(eth->src_mac, src_mac, sizeof(src_mac));
    mac_to_str(eth->dest_mac, dest_mac, sizeof(dest_mac));

    FILE *outputs[2] = { stdout, config->logfile };
    int nout = config->logfile ? 2 : 1;

    for (int o = 0; o < nout; o++) {
        FILE *out = outputs[o];
        if (!out) continue;

        fprintf(out, "{\"packet\":%d,\"size\":%zu,\"eth\":{\"src\":\"%s\",\"dst\":\"%s\",\"type\":\"0x%04X\"}",
                packet_num, raw_len, src_mac, dest_mac, eth->ethertype);

        if (ip) {
            char src_ip[16], dest_ip[16];
            ip_to_str(ip->src_ip, src_ip, sizeof(src_ip));
            ip_to_str(ip->dest_ip, dest_ip, sizeof(dest_ip));
            fprintf(out, ",\"ip\":{\"src\":\"%s\",\"dst\":\"%s\",\"proto\":\"%s\",\"ttl\":%u}",
                    src_ip, dest_ip, protocol_name(ip->protocol), ip->ttl);
        }

        if (tcp) {
            char flags[32];
            tcp_flags_to_str(tcp->flags, flags, sizeof(flags));
            fprintf(out, ",\"tcp\":{\"src_port\":%u,\"dst_port\":%u,\"flags\":\"%s\",\"seq\":%u}",
                    tcp->src_port, tcp->dest_port, flags, tcp->seq_num);
        }

        if (udp) {
            fprintf(out, ",\"udp\":{\"src_port\":%u,\"dst_port\":%u,\"len\":%u}",
                    udp->src_port, udp->dest_port, udp->length);
        }

        if (icmp) {
            fprintf(out, ",\"icmp\":{\"type\":%u,\"type_name\":\"%s\",\"code\":%u,\"id\":%u,\"seq\":%u}",
                    icmp->type, icmp_type_name(icmp->type), icmp->code,
                    icmp->identifier, icmp->sequence);
        }

        if (arp) {
            char sender_ip[16], target_ip[16], sender_mac[18], target_mac[18];
            ip_to_str(arp->sender_ip, sender_ip, sizeof(sender_ip));
            ip_to_str(arp->target_ip, target_ip, sizeof(target_ip));
            mac_to_str(arp->sender_mac, sender_mac, sizeof(sender_mac));
            mac_to_str(arp->target_mac, target_mac, sizeof(target_mac));
            fprintf(out, ",\"arp\":{\"op\":\"%s\",\"sender_ip\":\"%s\",\"sender_mac\":\"%s\","
                    "\"target_ip\":\"%s\",\"target_mac\":\"%s\"}",
                    arp_opcode_name(arp->opcode), sender_ip, sender_mac, target_ip, target_mac);
        }

        if (dns) {
            fprintf(out, ",\"dns\":{\"id\":%u,\"is_response\":%d,\"query\":\"%s\",\"type\":\"%s\","
                    "\"answers\":%u}",
                    dns->id, dns->is_response, dns->query_name,
                    dns_type_name(dns->query_type), dns->an_count);
        }

        fprintf(out, "}\n");
    }

    if (config->logfile)
        fflush(config->logfile);
}

/* ── Quiet output (one line per packet) ── */

static void output_quiet(const output_config_t *config, int packet_num,
                         size_t raw_len,
                         const eth_header_t *eth,
                         const ip_header_t *ip,
                         const tcp_header_t *tcp,
                         const udp_header_t *udp,
                         const icmp_header_t *icmp,
                         const arp_header_t *arp)
{
    (void)eth;
    char line[256];
    int pos = 0;

    pos += snprintf(line + pos, sizeof(line) - (size_t)pos, "#%-5d %5zu B  ", packet_num, raw_len);

    if (arp) {
        char sip[16], tip[16];
        ip_to_str(arp->sender_ip, sip, sizeof(sip));
        ip_to_str(arp->target_ip, tip, sizeof(tip));
        pos += snprintf(line + pos, sizeof(line) - (size_t)pos, "ARP %s %s → %s",
                        arp_opcode_name(arp->opcode), sip, tip);
    } else if (ip) {
        char sip[16], dip[16];
        ip_to_str(ip->src_ip, sip, sizeof(sip));
        ip_to_str(ip->dest_ip, dip, sizeof(dip));

        if (tcp) {
            char flags[32];
            tcp_flags_to_str(tcp->flags, flags, sizeof(flags));
            pos += snprintf(line + pos, sizeof(line) - (size_t)pos,
                            "TCP %s:%u → %s:%u [%s]",
                            sip, tcp->src_port, dip, tcp->dest_port, flags);
        } else if (udp) {
            pos += snprintf(line + pos, sizeof(line) - (size_t)pos,
                            "UDP %s:%u → %s:%u",
                            sip, udp->src_port, dip, udp->dest_port);
        } else if (icmp) {
            pos += snprintf(line + pos, sizeof(line) - (size_t)pos,
                            "ICMP %s → %s %s",
                            sip, dip, icmp_type_name(icmp->type));
        } else {
            pos += snprintf(line + pos, sizeof(line) - (size_t)pos,
                            "%s %s → %s",
                            protocol_name(ip->protocol), sip, dip);
        }
    } else {
        pos += snprintf(line + pos, sizeof(line) - (size_t)pos, "ETH 0x%04X", eth->ethertype);
    }

    (void)pos;

    if (config->color)
        printf("%s%s%s\n", COLOR_WHITE, line, COLOR_RESET);
    else
        printf("%s\n", line);

    if (config->logfile) {
        fprintf(config->logfile, "%s\n", line);
        fflush(config->logfile);
    }
}

/* ── Normal / Verbose output ── */

static void output_normal(const output_config_t *config, int packet_num,
                          size_t raw_len,
                          const eth_header_t *eth,
                          const ip_header_t *ip,
                          const tcp_header_t *tcp,
                          const udp_header_t *udp,
                          const icmp_header_t *icmp,
                          const arp_header_t *arp,
                          const dns_header_t *dns)
{
    int verbose = (config->mode == OUTPUT_MODE_VERBOSE);

    emit(config, COLOR_WHITE, "──────────────────────────────────────\n");
    emit(config, COLOR_BOLD, "Packet #%d\n", packet_num);

    /* Ethernet */
    {
        char src_mac[18], dest_mac[18];
        mac_to_str(eth->src_mac, src_mac, sizeof(src_mac));
        mac_to_str(eth->dest_mac, dest_mac, sizeof(dest_mac));
        emit(config, COLOR_MAGENTA, "[ETH] %s → %s | Type: 0x%04X\n",
             src_mac, dest_mac, eth->ethertype);
    }

    /* ARP */
    if (arp) {
        char sender_ip[16], target_ip[16], sender_mac[18], target_mac[18];
        ip_to_str(arp->sender_ip, sender_ip, sizeof(sender_ip));
        ip_to_str(arp->target_ip, target_ip, sizeof(target_ip));
        mac_to_str(arp->sender_mac, sender_mac, sizeof(sender_mac));
        mac_to_str(arp->target_mac, target_mac, sizeof(target_mac));
        emit(config, COLOR_YELLOW, "[ARP] %s (%s) → %s (%s) | Op: %s\n",
             sender_ip, sender_mac, target_ip, target_mac,
             arp_opcode_name(arp->opcode));
        if (verbose) {
            emit(config, COLOR_YELLOW, "      HW Type: %u | Proto: 0x%04X\n",
                 arp->hw_type, arp->proto_type);
        }
    }

    /* IP */
    if (ip) {
        char src_ip[16], dest_ip[16];
        ip_to_str(ip->src_ip, src_ip, sizeof(src_ip));
        ip_to_str(ip->dest_ip, dest_ip, sizeof(dest_ip));
        emit(config, COLOR_GREEN, "[IP]  %s → %s | Proto: %s | TTL: %u\n",
             src_ip, dest_ip, protocol_name(ip->protocol), ip->ttl);
        if (verbose) {
            emit(config, COLOR_GREEN, "      Ver: %u | IHL: %u | ToS: 0x%02X | TotLen: %u | ID: %u\n",
                 ip->version, ip->ihl, ip->tos, ip->total_length, ip->identification);
            emit(config, COLOR_GREEN, "      Flags/Frag: 0x%04X | Checksum: 0x%04X\n",
                 ip->flags_fragment, ip->checksum);
        }
    }

    /* TCP */
    if (tcp) {
        char flags[32];
        tcp_flags_to_str(tcp->flags, flags, sizeof(flags));
        emit(config, COLOR_CYAN, "[TCP] %u → %u | Flags: %s | Seq: %u\n",
             tcp->src_port, tcp->dest_port, flags, tcp->seq_num);
        if (verbose) {
            emit(config, COLOR_CYAN, "      Ack: %u | Win: %u | DOffset: %u | Urg: %u | Cksum: 0x%04X\n",
                 tcp->ack_num, tcp->window, tcp->data_offset, tcp->urgent_ptr, tcp->checksum);
        }
    }

    /* UDP */
    if (udp) {
        emit(config, COLOR_BLUE, "[UDP] %u → %u | Len: %u\n",
             udp->src_port, udp->dest_port, udp->length);
        if (verbose) {
            emit(config, COLOR_BLUE, "      Checksum: 0x%04X\n", udp->checksum);
        }
    }

    /* ICMP */
    if (icmp) {
        emit(config, COLOR_YELLOW, "[ICMP] Type: %u (%s) | Code: %u\n",
             icmp->type, icmp_type_name(icmp->type), icmp->code);
        if (verbose) {
            emit(config, COLOR_YELLOW, "       ID: %u | Seq: %u | Cksum: 0x%04X\n",
                 icmp->identifier, icmp->sequence, icmp->checksum);
        }
    }

    /* DNS */
    if (dns) {
        if (dns->is_response) {
            emit(config, COLOR_MAGENTA, "[DNS] Response | ID: %u | Answers: %u | Query: %s (%s)\n",
                 dns->id, dns->an_count, dns->query_name, dns_type_name(dns->query_type));
        } else {
            emit(config, COLOR_MAGENTA, "[DNS] Query | ID: %u | Name: %s | Type: %s\n",
                 dns->id, dns->query_name, dns_type_name(dns->query_type));
        }
    }

    emit(config, NULL, "Size: %zu bytes\n", raw_len);
}

/* ── Hex dump ── */

void output_hex_dump(const output_config_t *config,
                     const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        /* Offset */
        printf("  %04zx  ", i);
        if (config->logfile)
            fprintf(config->logfile, "  %04zx  ", i);

        /* Hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", data[i + j]);
                if (config->logfile)
                    fprintf(config->logfile, "%02x ", data[i + j]);
            } else {
                printf("   ");
                if (config->logfile)
                    fprintf(config->logfile, "   ");
            }
            if (j == 7) {
                printf(" ");
                if (config->logfile)
                    fprintf(config->logfile, " ");
            }
        }

        /* ASCII */
        printf(" |");
        if (config->logfile)
            fprintf(config->logfile, " |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            char c = (data[i + j] >= 32 && data[i + j] <= 126) ? (char)data[i + j] : '.';
            printf("%c", c);
            if (config->logfile)
                fprintf(config->logfile, "%c", c);
        }
        printf("|\n");
        if (config->logfile)
            fprintf(config->logfile, "|\n");
    }

    if (config->logfile)
        fflush(config->logfile);
}

/* ── Warning output ── */

void output_warning(const output_config_t *config, const char *fmt, ...)
{
    va_list args;
    char buf[512];

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (config->color)
        fprintf(stderr, "%s%s%s", COLOR_RED, buf, COLOR_RESET);
    else
        fprintf(stderr, "%s", buf);
}

/* ── Main dispatch ── */

void output_packet(const output_config_t *config, int packet_num,
                   const uint8_t *raw, size_t raw_len,
                   const eth_header_t *eth,
                   const ip_header_t *ip,
                   const tcp_header_t *tcp,
                   const udp_header_t *udp,
                   const icmp_header_t *icmp,
                   const arp_header_t *arp,
                   const dns_header_t *dns)
{
    switch (config->mode) {
    case OUTPUT_MODE_JSON:
        output_json(config, packet_num, raw_len, eth, ip, tcp, udp, icmp, arp, dns);
        break;
    case OUTPUT_MODE_QUIET:
        output_quiet(config, packet_num, raw_len, eth, ip, tcp, udp, icmp, arp);
        break;
    case OUTPUT_MODE_NORMAL:
    case OUTPUT_MODE_VERBOSE:
    default:
        output_normal(config, packet_num, raw_len, eth, ip, tcp, udp, icmp, arp, dns);
        break;
    }

    if (config->hex_dump) {
        output_hex_dump(config, raw, raw_len);
    }
}
