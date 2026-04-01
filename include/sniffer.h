#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdint.h>
#include <stddef.h>

/* Maximum packet size we can capture */
#define MAX_PACKET_SIZE 65536

/* Create a raw socket for packet capture. Returns socket fd or -1 on error. */
int sniffer_create_socket(const char *iface);

/* Capture a single packet into buf. Returns number of bytes received, or -1 on error. */
int sniffer_capture_packet(int sockfd, uint8_t *buf, size_t buf_size);

/* Record captured packets to a binary file. Returns 0 on success, -1 on error. */
int sniffer_record_packet(const char *filepath, const uint8_t *buf, size_t len);

/* Replay packets from a recorded binary file. Returns 0 on success, -1 on error. */
int sniffer_replay(const char *filepath);

#endif /* SNIFFER_H */
