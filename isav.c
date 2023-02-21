#include "src/probe.h"
#include "src/sniffer.h"

#define MAX_TARGETS 60000
#define MAX_ASN_LEN 8

pthread_t t1;
pthread_t t2;

struct Arg {
    struct Probe* p;
    int n;
};

void* sendPackets(void* arg_ptr) {
    struct Arg* arg = (struct Arg*) arg_ptr;
    sendEchoRequests(arg->p, arg->n, 0);
    return (void*) (NULL);
}

int measureRcv(struct Probe* probe, struct Probe* noiseMaker, int packets, int noisePackets,
               int wait_sec, const char* src, const char* dst, const char* fake_src) {
    struct SniffLog log;

    struct Arg arg1;
    arg1.p = probe;
    arg1.n = packets;

    struct Arg arg2;
    arg2.p = noiseMaker;
    arg2.n = noisePackets;

    log.captured = 0;

    prepareEchoRequest(probe, src, dst, 0, 0, 64);
    if (fake_src != NULL) prepareEchoRequest(noiseMaker, fake_src, dst, 0, 0, 64);
    setSnifferFilter("icmp6 and (ip6[40] == 1 or ip6[40] == 3)");
    startSniff(&log);

    if (fake_src != NULL) {
        pthread_create(&t2, NULL, sendPackets, (void*) (&arg2));
        pthread_create(&t1, NULL, sendPackets, (void*) (&arg1));
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
    } else {
        pthread_create(&t1, NULL, sendPackets, (void*) (&arg1));
        pthread_join(t1, NULL);
    }

    stopSniff(wait_sec * MILL);
    return log.captured;
}

void showTime() {
    long t        = time(NULL);
    struct tm* tm = localtime(&t);
    printf("Current Time: %02d/%02d/%02d %02d:%02d:%02d\n", tm->tm_year + 1900,
           tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
}

char prefixes[MAX_TARGETS][MAX_IPV6_NETWORK_LEN];
char as_numbers[MAX_TARGETS][MAX_ASN_LEN];
char targets[MAX_TARGETS][MAX_IPV6_ADDR_LEN];

// Set fake source address (either in the source network or in the target network)
// according to a reference address.
void setFakeSrc(char* ref, char* fake_src) {
    strcpy(fake_src, ref);
    int len = strlen(fake_src);
    int i   = len - 1;
    while (fake_src[i] == ':') {
        i--;
    }
    assert(i > 0);
    if (fake_src[i] != 'f') {
        fake_src[i] = 'f';
    } else {
        fake_src[i] = 'e';
    }
}

int main() {
    setbuf(stdout, NULL);

    parseConfig();

    char fake_src_here[MAX_IPV6_ADDR_LEN];   // Fake source address in the source network.
    char fake_src_there[MAX_IPV6_ADDR_LEN];  // Fake source address in the target network.

    setFakeSrc(CFG.src_ipv6_addr,
               fake_src_here);  // Set according to the real source IPv6 address.

    setSniffer(CFG.interface);

    struct Probe* probe    = (struct Probe*) malloc(sizeof(struct Probe));
    struct Probe* noiseMaker = (struct Probe*) malloc(sizeof(struct Probe));

    initProbe(probe, CFG.interface, (u8*) CFG.gateway_mac);
    initProbe(noiseMaker, CFG.interface, (u8*) CFG.gateway_mac);

    int wait_sec             = 5;
    int max_tries_per_prefix = 5;  // max tries in one prefix when encounting very strict
                                   // or very loose rate limiting

    char file_buf[FILE_BUFSIZE];

    char rvp[MAX_IPV6_ADDR_LEN];
    char dst[MAX_IPV6_ADDR_LEN];
    char prefix[MAX_IPV6_NETWORK_LEN];
    char as_number[MAX_ASN_LEN];
    char tmp_dst[MAX_IPV6_ADDR_LEN];
    int tmp_rcv;
    strcpy(tmp_dst, "Empty");

    FILE* fp = fopen("./data/RVPs.txt", "r");
    if (fp == NULL) {
        perror("Error: Cannot Open RVP File");
    }
    int i_prefix = -1;  // indicies of prefixes

    int tries_count = 0;
    showTime();
    int type = 1;
    while (fgets(file_buf, FILE_BUFSIZE, fp) != NULL) {
        if (file_buf[0] == '#') {  // Find the line with prefix information
            i_prefix++;
            if (strcmp(tmp_dst, "Empty") != 0) {
                strcpy(targets[i_prefix - 1], tmp_dst);
                int rcv = tmp_rcv;
                printf("[#%d, Type %d] Prefix: %s, AS Number: %s, "
                       "Target: %s. ",
                       i_prefix - 1 + 1, type, prefix, as_number, dst);
                printf("Rcv1: %d/%d.", rcv, CFG.iSAV_n);
            } else if (i_prefix > 0 && (strcmp(targets[i_prefix - 1], "Empty") == 0 ||
                                        strcmp(targets[i_prefix - 1], "Invalid") == 0)) {
                --i_prefix;
            }
            tries_count = 0;

            sscanf(file_buf, "# %s %s", prefix, as_number);

            strcpy(as_numbers[i_prefix], as_number);
            strcpy(prefixes[i_prefix], prefix);
            strcpy(targets[i_prefix], "Empty");
            strcpy(tmp_dst, "Empty");
        } else {
            if (strcmp(targets[i_prefix], "Empty") !=
                0) {  // If targets[number] is filled, move to next prefix.
                continue;
            } else {
                int icmp_type, icmp_code;
                sscanf(file_buf, "%s %d %d %s", rvp, &icmp_type, &icmp_code, dst);

                int rcv = measureRcv(probe, noiseMaker, CFG.iSAV_n, CFG.iSAV_m, wait_sec,
                                     CFG.src_ipv6_addr, dst, NULL);
                if (rcv <= 1 || rcv == CFG.iSAV_n) {
                    tries_count++;
                    if (rcv == 1 || rcv == CFG.iSAV_n) {
                        strcpy(tmp_dst, dst);
                        tmp_rcv = rcv;
                    }
                    int flag = 0;
                    if (tries_count >= max_tries_per_prefix) {
                        if (strcmp(tmp_dst, "Empty") != 0) {
                            strcpy(targets[i_prefix], tmp_dst);
                            strcpy(dst, tmp_dst);
                            flag = 1;
                            rcv  = tmp_rcv;
                        } else {
                            strcpy(targets[i_prefix], "Invalid");
                        }
                    }
                    if (!flag) continue;
                }

                strcpy(targets[i_prefix], dst);
                strcpy(tmp_dst, "Empty");
                printf("\n[#%d, Type %d] Prefix: %s, AS Number: %s, "
                       "Target: %s. ",
                       i_prefix + 1, type, prefix, as_number, dst);
                printf("Rcv1: %d/%d.", rcv, CFG.iSAV_n);
            }
        }
    }

    if (strcmp(tmp_dst, "Empty") != 0) {
        strcpy(targets[i_prefix], tmp_dst);
        int rcv = 1;
        printf("\n[#%d, Type %d] Prefix: %s, AS Number: %s, "
               "Target: %s. ",
               i_prefix + 1, type, prefix, as_number, dst);
        printf("Rcv1: %d/%d.", rcv, CFG.iSAV_n);
    } else if (strcmp(targets[i_prefix], "Empty") == 0 ||
               strcmp(targets[i_prefix], "Invalid") ==
                   0) {  // Remove the last invalid item.
        i_prefix--;
    }

    int n_prefixes = i_prefix + 1;  // total number of prefixes
    printf("\nMeasuring %d Prefix(es).\n", n_prefixes);
    while (1) {
        type++;
        if (type == 4) {
            type = 1;
        }
        printf("\n");
        showTime();
        printf("\n");
        for (int i = 0; i < n_prefixes; i++) {
            printf("\n[#%d, Type %d] Prefix: %s, AS Number: %s, Target: %s. ", i + 1,
                   type, prefixes[i], as_numbers[i], targets[i]);
            strcpy(dst, targets[i]);
            setFakeSrc(targets[i], fake_src_there);  // Set according to the IPv6 address
                                                     // of the measurement target.
            int rcv;
            switch (type) {
                case 1:
                    rcv = measureRcv(probe, noiseMaker, CFG.iSAV_n, CFG.iSAV_m, wait_sec,
                                     CFG.src_ipv6_addr, dst, NULL);
                    printf("Rcv1: %d/%d.", rcv, CFG.iSAV_n);
                    break;
                case 2:
                    rcv = measureRcv(probe, noiseMaker, CFG.iSAV_n, CFG.iSAV_m, wait_sec,
                                     CFG.src_ipv6_addr, dst, fake_src_here);
                    printf("Rcv2: %d/%d.", rcv, CFG.iSAV_n);
                    break;
                case 3:
                    rcv = measureRcv(probe, noiseMaker, CFG.iSAV_n, CFG.iSAV_m, wait_sec,
                                     CFG.src_ipv6_addr, dst, fake_src_there);
                    printf("Rcv3: %d/%d.", rcv, CFG.iSAV_n);
                    break;
            }
        }
    }
    fclose(fp);
    return 0;
}