#ifndef OUTPUT_H
#define OUTPUT_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "parser.h"

/* Output modes */
#define OUTPUT_MODE_NORMAL  0
#define OUTPUT_MODE_VERBOSE 1
#define OUTPUT_MODE_QUIET   2
#define OUTPUT_MODE_JSON    3

/* Output configuration */
typedef struct {
    int  mode;           /* OUTPUT_MODE_* */
    int  color;          /* 1 = color enabled */
    int  hex_dump;       /* 1 = show hex dump */
    FILE *logfile;       /* optional log file */
} output_config_t;

/* ANSI color codes */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"

/* Initialize output config with defaults. */
void output_init(output_config_t *config);

/* Print a parsed packet according to output config.
   Pass NULL for any layer that wasn't parsed. */
void output_packet(const output_config_t *config, int packet_num,
                   const uint8_t *raw, size_t raw_len,
                   const eth_header_t *eth,
                   const ip_header_t *ip,
                   const tcp_header_t *tcp,
                   const udp_header_t *udp,
                   const icmp_header_t *icmp,
                   const arp_header_t *arp,
                   const dns_header_t *dns);

/* Print hex dump of raw bytes. */
void output_hex_dump(const output_config_t *config,
                     const uint8_t *data, size_t len);

/* Print an anomaly warning. */
void output_warning(const output_config_t *config, const char *fmt, ...);

#endif /* OUTPUT_H */
