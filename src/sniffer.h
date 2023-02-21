#ifndef SNIFFER_H
#define SNIFFER_H

#include "common.h"
#include <pcap.h>

#define SNIFFER_BUFSIZE 1000

extern char errBuf[PCAP_ERRBUF_SIZE];

extern pcap_t* sniffer;
extern struct bpf_program filter;

extern pthread_t sniff_thread;

struct SniffLog {
    int captured;
    struct timeval tv[SNIFFER_BUFSIZE];
};

void setSniffer(const char* interface);
void setSnifferFilter(const char* my_filter);
void processPacket(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void* doSniff(void*);
void* doSniffOne(void*);
void startSniff(struct SniffLog*);
void startSniffOne(struct SniffLog*);
void stopSniff(unsigned int wait_usec);
void stopSniffIfReceived(unsigned int time_out_usec);
#endif