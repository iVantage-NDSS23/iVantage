#ifndef COMMON_H
#define COMMON_H

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_IPV6_ADDR_LEN 46
#define MAX_IPV6_NETWORK_LEN 50
#define IPV6_ADDR_BYTES 16
#define MAC_ADDR_BYTES 6
#define MAX_INTERFACE_NAME 16

#define BUFSIZE 1500
#define FILE_BUFSIZE 255
#define CONFIG_ATTR_MAXLEN MAX_IPV6_NETWORK_LEN

#define MILL 1000000
#define KILO 1000

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct IPv6Header {
    u32 first_four_bytes;  // 32 Bits = Version (4 Bits) + Traffic Class (8
                           // Bits) + Flow Label (24 Bits);
    u16 plen;              // 16 Bits
    u8 nh;                 // 8 Bits
    u8 hlim;               // 8 Bits
    u8 src[16];
    u8 dst[16];
};

struct ICMPv6Header {
    u8 type;       // 8 Bits
    u8 code;       // 8 Bits
    u16 checksum;  // 16 Bits
};

struct ICMPv6EchoRequestHeader {
    u16 id;   // 16 Bits
    u16 seq;  // 16 Bits
    // char* data;
};

struct PseudoHeader {
    u8 src[16];
    u8 dst[16];
    u32 upperlen;
    u8 zeros[3];
    u8 nh;
};

struct Probe {
    int bytes;
    struct IPv6Header* ipv6hdr;
    struct ICMPv6Header* icmp6hdr;
    struct PseudoHeader* pseudohdr;
    u8 sendbuf[BUFSIZE];
    u8 recvbuf[BUFSIZE];
    struct sockaddr_ll src_sockaddr;
    struct sockaddr_ll dst_sockaddr;
    int sockfd;
};

struct Config {
    char src_ipv6_addr[MAX_IPV6_ADDR_LEN];
    char interface[MAX_INTERFACE_NAME];
    u8 gateway_mac[MAC_ADDR_BYTES];
    int iSAV_n;
    int iSAV_m;
    int RVPing_n;
    int RVPing_m;
};

void parseConfig();

extern struct Config CFG;

#endif