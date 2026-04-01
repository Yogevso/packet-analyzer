#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include "sniffer.h"
#include "parser.h"
#include "filters.h"
#include "analyzer.h"
#include "output.h"
#include "stats.h"

static volatile int running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Capture Options:\n");
    printf("  --iface IFACE      Capture on specific interface (e.g. eth0)\n");
    printf("  --count N          Capture N packets then exit (0 = unlimited)\n");
    printf("  --record FILE      Record raw packets to binary file\n");
    printf("  --replay FILE      Replay packets from a recorded file\n");
    printf("\n");
    printf("Filter Options:\n");
    printf("  --tcp              Show only TCP packets\n");
    printf("  --udp              Show only UDP packets\n");
    printf("  --icmp             Show only ICMP packets\n");
    printf("  --arp              Show only ARP packets\n");
    printf("  --port PORT        Filter by port number\n");
    printf("  --ip ADDRESS       Filter by IPv4 address\n");
    printf("\n");
    printf("Output Options:\n");
    printf("  --verbose          Verbose output (all header fields)\n");
    printf("  --quiet            One-line-per-packet summary\n");
    printf("  --json             JSON output (one object per line)\n");
    printf("  --hex              Show hex dump of each packet\n");
    printf("  --color            Enable colored output\n");
    printf("  --stats            Show live statistics line\n");
    printf("  --log FILE         Log output to file\n");
    printf("\n");
    printf("Anomaly Options:\n");
    printf("  --anomaly-config FILE  Load anomaly rules from config file\n");
    printf("\n");
    printf("  -h, --help         Show this help message\n");
}

int main(int argc, char *argv[])
{
    filter_config_t filter;
    filter_init(&filter);

    output_config_t out_cfg;
    output_init(&out_cfg);

    anomaly_config_t anomaly_cfg;
    anomaly_config_init(&anomaly_cfg);

    const char *iface           = NULL;
    const char *log_path        = NULL;
    const char *record_path     = NULL;
    const char *replay_path     = NULL;
    const char *anomaly_cfg_path = NULL;
    int max_count   = 0;
    int live_stats  = 0;

    /* ── Parse CLI arguments ── */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tcp") == 0) {
            filter.tcp_only = 1;
        } else if (strcmp(argv[i], "--udp") == 0) {
            filter.udp_only = 1;
        } else if (strcmp(argv[i], "--icmp") == 0) {
            filter.icmp_only = 1;
        } else if (strcmp(argv[i], "--arp") == 0) {
            filter.arp_only = 1;
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            long p = strtol(argv[++i], NULL, 10);
            if (p <= 0 || p > 65535) {
                fprintf(stderr, "[ERROR] Invalid port: %s\n", argv[i]);
                return 1;
            }
            filter.port = (uint16_t)p;
        } else if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc) {
            filter.ip_filter = filter_parse_ip(argv[++i]);
            if (filter.ip_filter == 0)
                return 1;
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            iface = argv[++i];
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strcmp(argv[i], "--record") == 0 && i + 1 < argc) {
            record_path = argv[++i];
        } else if (strcmp(argv[i], "--replay") == 0 && i + 1 < argc) {
            replay_path = argv[++i];
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            max_count = (int)strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            out_cfg.mode = OUTPUT_MODE_VERBOSE;
        } else if (strcmp(argv[i], "--quiet") == 0) {
            out_cfg.mode = OUTPUT_MODE_QUIET;
        } else if (strcmp(argv[i], "--json") == 0) {
            out_cfg.mode = OUTPUT_MODE_JSON;
        } else if (strcmp(argv[i], "--hex") == 0) {
            out_cfg.hex_dump = 1;
        } else if (strcmp(argv[i], "--color") == 0) {
            out_cfg.color = 1;
        } else if (strcmp(argv[i], "--stats") == 0) {
            live_stats = 1;
        } else if (strcmp(argv[i], "--anomaly-config") == 0 && i + 1 < argc) {
            anomaly_cfg_path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "[ERROR] Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* ── Load anomaly config if specified ── */
    if (anomaly_cfg_path) {
        if (anomaly_config_load(&anomaly_cfg, anomaly_cfg_path) != 0)
            return 1;
    }

    /* ── Replay mode ── */
    if (replay_path) {
        return sniffer_replay(replay_path) == 0 ? 0 : 1;
    }

    /* ── Create raw socket ── */
    int sockfd = sniffer_create_socket(iface);
    if (sockfd < 0)
        return 1;

    /* ── Open log file ── */
    if (log_path) {
        out_cfg.logfile = fopen(log_path, "a");
        if (!out_cfg.logfile) {
            perror("[ERROR] Failed to open log file");
            close(sockfd);
            return 1;
        }
    }

    /* ── Init ARP cache for spoofing detection ── */
    arp_cache_reset();

    /* ── Init statistics ── */
    packet_stats_t stats;
    stats_init(&stats);

    /* ── Register signal handlers for clean shutdown ── */
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    if (out_cfg.mode != OUTPUT_MODE_JSON) {
        printf("[INFO] Packet Analyzer started. Press Ctrl+C to stop.\n");
        if (iface)            printf("[IFACE] %s\n", iface);
        if (filter.tcp_only)  printf("[FILTER] TCP only\n");
        if (filter.udp_only)  printf("[FILTER] UDP only\n");
        if (filter.icmp_only) printf("[FILTER] ICMP only\n");
        if (filter.arp_only)  printf("[FILTER] ARP only\n");
        if (filter.port)      printf("[FILTER] Port: %u\n", filter.port);
        if (filter.ip_filter) {
            char ip_buf[16];
            ip_to_str(filter.ip_filter, ip_buf, sizeof(ip_buf));
            printf("[FILTER] IP: %s\n", ip_buf);
        }
        if (record_path)      printf("[RECORD] Saving to: %s\n", record_path);
        if (log_path)         printf("[LOG] Writing to: %s\n", log_path);
        if (out_cfg.color)    printf("[COLOR] Enabled\n");
        printf("\n");
    }

    /* ── Main capture loop ── */
    uint8_t buffer[MAX_PACKET_SIZE];
    int packet_count = 0;
    time_t last_live_print = 0;

    while (running) {
        int len = sniffer_capture_packet(sockfd, buffer, sizeof(buffer));
        if (len < 0) {
            if (running)
                fprintf(stderr, "[ERROR] Capture failed\n");
            break;
        }

        /* ── Parse Ethernet ── */
        eth_header_t eth;
        if (parse_ethernet(buffer, (size_t)len, &eth) != 0)
            continue;

        /* ── Parse protocol layers ── */
        ip_header_t ip;
        ip_header_t *ip_ptr = NULL;
        tcp_header_t tcp;
        tcp_header_t *tcp_ptr = NULL;
        udp_header_t udp;
        udp_header_t *udp_ptr = NULL;
        icmp_header_t icmp;
        icmp_header_t *icmp_ptr = NULL;
        arp_header_t arp;
        arp_header_t *arp_ptr = NULL;
        dns_header_t dns;
        dns_header_t *dns_ptr = NULL;

        if (eth.ethertype == ETH_TYPE_ARP) {
            const uint8_t *arp_data = buffer + ETH_HEADER_LEN;
            size_t arp_data_len = (size_t)len - ETH_HEADER_LEN;
            if (parse_arp(arp_data, arp_data_len, &arp) == 0)
                arp_ptr = &arp;
        } else if (eth.ethertype == ETH_TYPE_IP) {
            const uint8_t *ip_data = buffer + ETH_HEADER_LEN;
            size_t ip_data_len = (size_t)len - ETH_HEADER_LEN;

            if (parse_ip(ip_data, ip_data_len, &ip) == 0) {
                ip_ptr = &ip;
                size_t ip_hdr_len = (size_t)ip.ihl * 4;
                const uint8_t *payload = ip_data + ip_hdr_len;
                size_t payload_len = ip_data_len > ip_hdr_len ? ip_data_len - ip_hdr_len : 0;

                if (ip.protocol == IP_PROTO_TCP && payload_len >= 20) {
                    if (parse_tcp(payload, payload_len, &tcp) == 0)
                        tcp_ptr = &tcp;
                } else if (ip.protocol == IP_PROTO_UDP && payload_len >= 8) {
                    if (parse_udp(payload, payload_len, &udp) == 0) {
                        udp_ptr = &udp;
                        /* Check for DNS */
                        if (udp.src_port == DNS_PORT || udp.dest_port == DNS_PORT) {
                            if (payload_len > 8) {
                                if (parse_dns(payload + 8, payload_len - 8, &dns) == 0)
                                    dns_ptr = &dns;
                            }
                        }
                    }
                } else if (ip.protocol == IP_PROTO_ICMP && payload_len >= 8) {
                    if (parse_icmp(payload, payload_len, &icmp) == 0)
                        icmp_ptr = &icmp;
                }
            }
        }

        /* ── Apply filters ── */
        if (!filter_match(&filter, eth.ethertype, ip_ptr, tcp_ptr, udp_ptr))
            continue;

        /* ── Increment counter ── */
        packet_count++;

        /* ── Update statistics ── */
        uint32_t s_ip = ip_ptr ? ip_ptr->src_ip : 0;
        uint32_t d_ip = ip_ptr ? ip_ptr->dest_ip : 0;
        uint8_t proto = ip_ptr ? ip_ptr->protocol : 0;
        stats_update(&stats, (size_t)len, proto, s_ip, d_ip,
                     arp_ptr != NULL, dns_ptr != NULL);

        /* ── Output (skip individual packets in live-stats-only mode) ── */
        if (!live_stats) {
            output_packet(&out_cfg, packet_count, buffer, (size_t)len,
                          &eth, ip_ptr, tcp_ptr, udp_ptr, icmp_ptr, arp_ptr, dns_ptr);
        }

        /* ── Anomaly detection ── */
        int anom = analyze_packet(&anomaly_cfg, buffer, (size_t)len,
                                  ip_ptr, tcp_ptr, udp_ptr);

        /* ARP spoofing check */
        if (arp_ptr && anomaly_cfg.check_arp_spoofing) {
            anom += check_arp_spoofing(arp_ptr);
        }

        if (anom > 0)
            stats_add_anomaly(&stats, anom);

        /* ── Record if requested ── */
        if (record_path) {
            sniffer_record_packet(record_path, buffer, (size_t)len);
        }

        /* ── Live stats (update every second) ── */
        if (live_stats) {
            time_t now = time(NULL);
            if (now != last_live_print) {
                stats_print_live(&stats);
                last_live_print = now;
            }
        }

        /* ── Check count limit ── */
        if (max_count > 0 && packet_count >= max_count) {
            if (out_cfg.mode != OUTPUT_MODE_JSON)
                printf("\n[INFO] Reached packet limit (%d)\n", max_count);
            break;
        }
    }

    /* ── Print summary ── */
    if (live_stats)
        printf("\n");  /* newline after live stats line */

    if (out_cfg.mode != OUTPUT_MODE_JSON) {
        stats_print_summary(&stats, stdout);
        if (out_cfg.logfile)
            stats_print_summary(&stats, out_cfg.logfile);
    }

    /* ── Cleanup ── */
    close(sockfd);
    if (out_cfg.logfile)
        fclose(out_cfg.logfile);

    return 0;
}
