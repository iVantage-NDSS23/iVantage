#include "src/probe.h"
#include "src/sniffer.h"

// This program tests whether the packets with spoofed source addresses can be sent to the
// Internet. You should sniff packets on the destination IPv6 address to identify
// whether the spoofed packets are filtered.

int main() {
    setbuf(stdout, NULL);
    parseConfig();

    struct Probe* probe = (struct Probe*) malloc(sizeof(struct Probe));
    initProbe(probe, CFG.interface, (u8*) CFG.gateway_mac);

    const char* dst      = "2001:1";
    const char* fake_src = "2001:2";

    // Send packets with real source address
    prepareEchoRequest(probe, CFG.src_ipv6_addr, dst, 0, 0, 64);
    sendEchoRequests(probe, 1, 0);

    // Send packets with spoofed source address
    prepareEchoRequest(probe, fake_src, dst, 0, 0, 64);
    sendEchoRequests(probe, 1, 0);

    return 0;
}