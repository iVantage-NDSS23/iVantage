#include "probe.h"

void initProbe(struct Probe* p, const char* ifname, u8* gateway_mac) {
    p->bytes = 0;
    if ((p->sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6))) < 0) {
        perror("Raw Socket Created Failure.");
        exit(1);
    }
    p->ipv6hdr  = (struct IPv6Header*) p->sendbuf;
    p->icmp6hdr = (struct ICMPv6Header*) (p->sendbuf + 40);
    setEthernet(p, ifname, gateway_mac);
}

u16 calculateChecksum(struct Probe* p, const char* src, const char* dst) {
    p->pseudohdr = (struct PseudoHeader*) ((u8*) p->icmp6hdr + p->bytes);
    inet_pton(AF_INET6, src, p->pseudohdr->src);
    inet_pton(AF_INET6, dst, p->pseudohdr->dst);
    p->pseudohdr->upperlen = htonl(p->bytes);
    memset(p->pseudohdr->zeros, 0, 3);
    p->pseudohdr->nh         = 58;
    int bytes_with_pseudohdr = p->bytes + 40;
    u32 checksum             = 0;
    u16* ptr;
    int words;
    ptr   = (u16*) p->icmp6hdr;
    words = (bytes_with_pseudohdr + 1) / 2;
    while (words--) {
        checksum += ntohs(*ptr);
        ptr++;
    }
    while (checksum & 0xffff0000)
        checksum = (checksum >> 16) + (checksum & 0xffff);
    return ~((u16) checksum);
}

void prepareEchoRequest(struct Probe* p, const char* src, const char* dst, u16 id,
                        u16 seq, u8 hlim) {
    buildEchoRequestPacket(p, NULL, 0, src, dst, id, seq);
    buildIPv6Packet(p, src, dst, hlim, 58);
    u8* ptr = (u8*) p->sendbuf;
}

void sendEchoRequests(struct Probe* p, int n, double pps) {
    int ret;
    while (n--) {
        ret = sendto(p->sockfd, p->sendbuf, p->bytes + 40, 0,
                     (struct sockaddr*) &p->dst_sockaddr, sizeof(p->dst_sockaddr));
        if (ret < 0) {
            perror("Send Failure.");
            exit(1);
        }
        if (pps != 0) { usleep((unsigned int) (1000000 / pps - 166)); }
    }
}

void setEthernet(struct Probe* p, const char* ifname, u8* gateway_mac) {
    struct ifreq req;
    memset(&req, 0, sizeof(req));
    strcpy((char*) req.ifr_name, (const char*) ifname);
    if (ioctl(p->sockfd, SIOCGIFINDEX, &req) < 0) {
        perror("init: ioctl");
        close(p->sockfd);
        return;
    }
    memset((void*) &p->dst_sockaddr, 0, sizeof(p->dst_sockaddr));
    p->dst_sockaddr.sll_family   = PF_PACKET;
    p->dst_sockaddr.sll_protocol = htons(ETH_P_IPV6);
    p->dst_sockaddr.sll_ifindex  = req.ifr_ifindex;
    p->dst_sockaddr.sll_halen    = ETH_ALEN;
    memcpy((void*) (p->dst_sockaddr.sll_addr), (void*) gateway_mac, ETH_ALEN);
}
void buildEchoRequestPacket(struct Probe* p, char* data, int data_size, const char* src,
                            const char* dst, u16 id, u16 seq) {
    p->bytes = 0;
    memset(p->sendbuf, 0, sizeof(p->sendbuf));
    p->icmp6hdr->type     = 128;
    p->icmp6hdr->code     = 0;
    p->icmp6hdr->checksum = 0;
    struct ICMPv6EchoRequestHeader* echohdr =
        (struct ICMPv6EchoRequestHeader*) ((u8*) p->icmp6hdr + 4);
    echohdr->id  = htons(id);
    echohdr->seq = htons(seq);
    p->bytes += 8;
    if (data_size > 0) {
        memcpy(echohdr + 4, data, data_size);
        p->bytes += data_size;
    }
    p->icmp6hdr->checksum = htons(calculateChecksum(p, src, dst));
}

void buildIPv6Packet(struct Probe* p, const char* src, const char* dst, u8 hlim, u8 nh) {
    p->ipv6hdr->first_four_bytes = 0x00000060;  // htnol
    // p->ipv6hdr->first_four_bytes = 0x1faf0660;  // htnol
    p->ipv6hdr->plen = htons(p->bytes);
    p->ipv6hdr->nh   = nh;
    p->ipv6hdr->hlim = hlim;
    memcpy(p->ipv6hdr->src, p->pseudohdr->src, 16);
    memcpy(p->ipv6hdr->dst, p->pseudohdr->dst, 16);
}
