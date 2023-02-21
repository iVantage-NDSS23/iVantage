#include "src/probe.h"
#include "src/sniffer.h"
#include <assert.h>
#include <getopt.h>

#define TIMEOUT 10 * KILO
#define SNIFFER_FILTER_MAXLEN 100
#define MAX_MEASUREMENT_TIMES 20
#define EPS 0.2
#define RTT_TEST_TIMES 3

int rcv1[MAX_MEASUREMENT_TIMES];
int rcv2[MAX_MEASUREMENT_TIMES];

long getTimeDiff(struct timeval* a, struct timeval* b) {
    long us = b->tv_usec - a->tv_usec;
    long s  = b->tv_sec - a->tv_sec;
    return s * 1000000 + us;
}

double getRTT(struct Probe* p, const char* dst, const char* src) {
    prepareEchoRequest(p, src, dst, 0, 0, 64);

    struct timeval send_tv;
    unsigned int sniff_time = MILL;

    struct SniffLog log;

    startSniffOne(&log);
    gettimeofday(&send_tv, 0);

    sendEchoRequests(p, 1, 0);

    stopSniff(sniff_time);

    if (log.captured == 0) {
        printf("\t[ERROR] No Replies.\n");
        return -1;
    } else if (log.captured > 1) {
        printf("\t[ERROR] Too Many Replies Received.\n");
        return -1;
    } else {
        double rtt = (double) getTimeDiff(&send_tv, &log.tv[0]) / 1000;
        if (rtt < 0) {
            printf("\t[ERROR] RTT Measured is Negative.\n");
        }
        return rtt;
    }
}

double getMinRTT(struct Probe* p, const char* dst, const char* src, int n_measure,
                 double interval_sec) {
    char my_filter[SNIFFER_FILTER_MAXLEN];
    sprintf(my_filter, "icmp6 and ip6[40] == 129 and (src host %s)", dst);
    setSnifferFilter(my_filter);
    double min_rtt = TIMEOUT;
    double rtt;
    for (int i = 0; i < n_measure; i++) {
        rtt = getRTT(p, dst, src);
        if (rtt < 0) {
            rtt = TIMEOUT;
        }
        if (rtt < min_rtt) {
            min_rtt = rtt;
        }
        usleep(interval_sec * MILL);
    }

    assert(rtt < TIMEOUT);
    return min_rtt;
}

void rvping(struct Probe* probe, struct Probe* noiseMaker, const char* src,
            const char* rvp, const char* rvpTarget, const char* target, int packets,
            int noisePackets, double specified_rtt, double threshold,
            int measurement_times) {
    printf("* Target: %s\n* RVP: %s, RVP Target: %s\n", target, rvp, rvpTarget);

    printf("\n");

    printf("[Step 1] Estimating Δt.\n");

    double rtt_a = getMinRTT(probe, rvp, src, RTT_TEST_TIMES, 1);
    double rtt_b = getMinRTT(probe, target, src, RTT_TEST_TIMES, 1);

    printf("\tRTT between RVP: %.2lf ms\n\tRTT between Target: %.2lf ms\n", rtt_a, rtt_b);
    double estimatedLow  = (rtt_a > rtt_b) ? (rtt_a - rtt_b) : (rtt_b - rtt_a);
    double estimatedHigh = rtt_a + rtt_b;

    printf("\tEstimated RTT Range: (%.2lf, %.2lf) "
           "ms\n",
           estimatedLow, estimatedHigh);

    srand(time(NULL));
    double estimatedRTT =
        estimatedLow + (estimatedHigh - estimatedLow) * ((double) rand() / RAND_MAX);

    if (specified_rtt > 0) {
        estimatedRTT = specified_rtt;
        printf("\tRTT between RVP and Target is Specified: %.2lf ms\n", estimatedRTT);
    } else {
        printf("\tEstimated RTT between RVP and Target: %.2lf ms\n", estimatedRTT);
    }

    double delta_t = (rtt_b - rtt_a + estimatedRTT) / 2;
    printf("\tΔt = %.2lf ms\n", delta_t);

    // setSnifferFilter("icmp6 and (ip6[40] == 1 or ip6[40] == 3)");
    char my_filter[SNIFFER_FILTER_MAXLEN];
    sprintf(my_filter, "icmp6 and (ip6[40] == 1 or ip6[40] == 3) and (src host %s)", rvp);
    setSnifferFilter(my_filter);

    for (int round = 1; round <= measurement_times; round++) {
        printf("[Round %d/%d] [Step 2] Measuring rcv1...", round, measurement_times);

        struct SniffLog log;
        log.captured = 0;

        startSniff(&log);
        prepareEchoRequest(probe, src, rvpTarget, 0, 0, 64);
        sendEchoRequests(probe, packets, 0);

        stopSniff(5 * MILL);

        rcv1[round - 1] = log.captured;
        printf("\trcv1 = %d\n", log.captured);

        usleep(10 * MILL);

        printf("[Round %d/%d] [Step 3] Measuring rcv2...", round, measurement_times);
        log.captured = 0;

        startSniff(&log);

        prepareEchoRequest(noiseMaker, rvpTarget, target, 0, 0, 64);

        if (delta_t > 0) {
            sendEchoRequests(noiseMaker, noisePackets, 0);
            usleep((unsigned int) (delta_t * KILO));
            sendEchoRequests(probe, packets, 0);
        } else {
            delta_t = -delta_t;
            sendEchoRequests(probe, packets, 0);
            usleep((unsigned int) (delta_t * 1000));
            sendEchoRequests(noiseMaker, noisePackets, 0);
        }

        stopSniff(5 * MILL);

        rcv2[round - 1] = log.captured;
        printf("\trcv2 = %d\n", log.captured);

        if (round < measurement_times && specified_rtt == 0) {
            estimatedRTT = estimatedLow +
                           (estimatedHigh - estimatedLow) * ((double) rand() / RAND_MAX);

            printf("\tTry New Estimated RTT between RVP and Target: %.2lf ms\n",
                   estimatedRTT);

            double delta_t = (rtt_b - rtt_a + estimatedRTT) / 2;
            printf("\tTry New Δt = %.2lf ms\n", delta_t);
        }
    }

    printf("\n");
    printf("* Result:\n");

    double rcv1_avg = 0;
    double rcv2_avg = 0;

    for (int round = 0; round < measurement_times; round++) {
        rcv1_avg += rcv1[round];
        rcv2_avg += rcv2[round];
    }

    rcv1_avg /= measurement_times;
    rcv2_avg /= measurement_times;

    printf("* Average: rcv1 = %.2f, rcv2 = %.2f\n", rcv1_avg, rcv2_avg);

    printf("* Reachability is ");

    if (rcv1_avg <= EPS) {
        printf("UNCERTAIN\n");
        printf("\tThe RVP you select may be invalid. It doesn't reply to our probes.\n");
        return;
    }

    if (rcv1_avg <= 1 + EPS) {
        printf("UNCERTAIN\n");
        printf(
            "\tThe RVP you select implements with very strict ICMP rate limiting, which "
            "pose "
            "challenges to the measurements. We recommend you select an RVP with "
            "moderate ICMP rate "
            "limiting.\n");
        return;
    }

    if (rcv1_avg >= packets - EPS) {
        printf("UNCERTAIN\n");
        printf(
            "\tThe RVP you select implements with very loose ICMP rate limiting, which "
            "pose "
            "challenges to the measurements. We recommend you select an RVP with "
            "moderate ICMP rate "
            "limiting.\n");
        return;
    }

    if (rcv2_avg > rcv1_avg * threshold) {
        printf("UNREACHABLE\n");
    } else {
        printf("REACHABLE\n");
    }
}

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);
    parseConfig();

    setSniffer(CFG.interface);

    int measurement_times = 3;
    double threshold      = 0.6;
    double specified_rtt  = 0;

    struct Probe* probe = (struct Probe*) malloc(sizeof(struct Probe));
    initProbe(probe, CFG.interface, (u8*) CFG.gateway_mac);

    struct Probe* noiseMaker = (struct Probe*) malloc(sizeof(struct Probe));
    initProbe(noiseMaker, CFG.interface, (u8*) CFG.gateway_mac);

    char rvp[MAX_IPV6_ADDR_LEN];
    char rvp_target[MAX_IPV6_ADDR_LEN];
    char target[MAX_IPV6_ADDR_LEN];

    int ch;

    while ((ch = getopt(argc, argv, "a:b:x:r::t::n::")) != -1) {
        switch (ch) {
            case 'a': strcpy(rvp, optarg); break;
            case 'b': strcpy(target, optarg); break;
            case 'x': strcpy(rvp_target, optarg); break;
            case 'r': specified_rtt = atof(optarg); break;
            case 't': threshold = atof(optarg); break;
            case 'n': measurement_times = atoi(optarg); break;
            case '?': printf(">> Unknown option: %c\n", (char) optopt); break;
        }
    }

    rvping(probe, noiseMaker, CFG.src_ipv6_addr, rvp, rvp_target, target, CFG.RVPing_n,
           CFG.RVPing_m, specified_rtt, threshold, measurement_times);
    return 0;
}