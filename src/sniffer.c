#include "sniffer.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>

int sniffer_create_socket(const char *iface)
{
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("[ERROR] Failed to create raw socket (run as root)");
        return -1;
    }

    /* Bind to specific interface if requested */
    if (iface) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

        if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
            perror("[ERROR] Failed to get interface index");
            close(sockfd);
            return -1;
        }

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family   = AF_PACKET;
        sll.sll_ifindex  = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("[ERROR] Failed to bind to interface");
            close(sockfd);
            return -1;
        }
    }

    return sockfd;
}

int sniffer_capture_packet(int sockfd, uint8_t *buf, size_t buf_size)
{
    ssize_t n = recvfrom(sockfd, buf, buf_size, 0, NULL, NULL);
    if (n < 0) {
        perror("[ERROR] recvfrom failed");
        return -1;
    }
    return (int)n;
}

int sniffer_record_packet(const char *filepath, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(filepath, "ab");
    if (!f) {
        perror("[ERROR] Failed to open record file");
        return -1;
    }

    /* Write packet length (4 bytes) followed by packet data */
    uint32_t pkt_len = (uint32_t)len;
    if (fwrite(&pkt_len, sizeof(pkt_len), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    if (fwrite(buf, 1, len, f) != len) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

int sniffer_replay(const char *filepath)
{
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        perror("[ERROR] Failed to open replay file");
        return -1;
    }

    uint8_t buf[MAX_PACKET_SIZE];
    uint32_t pkt_len;
    int count = 0;

    while (fread(&pkt_len, sizeof(pkt_len), 1, f) == 1) {
        if (pkt_len > MAX_PACKET_SIZE) {
            fprintf(stderr, "[ERROR] Corrupt record: packet size %u exceeds max\n", pkt_len);
            fclose(f);
            return -1;
        }
        if (fread(buf, 1, pkt_len, f) != pkt_len) {
            fprintf(stderr, "[ERROR] Truncated packet in record file\n");
            fclose(f);
            return -1;
        }
        count++;
        printf("=== Replayed Packet #%d (%u bytes) ===\n", count, pkt_len);
    }

    printf("[INFO] Replay complete: %d packets\n", count);
    fclose(f);
    return 0;
}
