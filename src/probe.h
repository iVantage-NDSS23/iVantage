#ifndef PROBE_H
#define PROBE_H

#include "common.h"

void initProbe(struct Probe* p, const char* ifname, u8* gateway_mac);
u16 calculateChecksum(struct Probe* p, const char* src, const char* dst);
void prepareEchoRequest(struct Probe* p, const char* src, const char* dst, u16 id,
                        u16 seq, u8 hlim);
void sendEchoRequests(struct Probe* p, int n, double pps);

void setEthernet(struct Probe* p, const char* ifname, u8* gateway_mac);
void buildEchoRequestPacket(struct Probe* p, char* data, int data_size, const char* src,
                            const char* dst, u16 id, u16 seq);
void buildIPv6Packet(struct Probe* p, const char* src, const char* dst, u8 hlim, u8 nh);

#endif