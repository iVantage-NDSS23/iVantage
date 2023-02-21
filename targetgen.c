#include "src/common.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TARGET_NUMBER 65536

static u8 targets[MAX_TARGET_NUMBER][IPV6_ADDR_BYTES];
static int n_target = 0;

void randomizeIID(u8* iid) {
    for (int i = 0; i < 8; i++) {
        iid[i] = rand() % 256;
    }
}

void generateScanningTargets(const char* prefix) {
    srand((unsigned int) time(NULL));

    char prefix_backup[MAX_IPV6_NETWORK_LEN];
    strcpy(prefix_backup, prefix);

    int i_slash = (int) strlen(prefix_backup) - 1;
    while (i_slash > 0 && prefix_backup[i_slash] != '/') {
        i_slash--;
    }
    assert(i_slash > 0);

    int len = atoi(&prefix_backup[i_slash + 1]);

    assert(len < 64);  // Make sure prefix length < 64.

    prefix_backup[i_slash] = '\0';

    u8 dst[IPV6_ADDR_BYTES];

    inet_pton(AF_INET6, prefix_backup, dst);
    int start_pos = len / 8;
    int remainder = len % 8;

    // Get a mask to clear bits before the prefix length,
    // e.g.: reminder = 0 -> 0, reminder = 2 -> 11000000
    u8 first_byte_mask = ~((1 << (8 - remainder)) - 1);

    // Make bits before prefix length zeros (e.g., 44th->64th bits), but the remainder in
    // the same byte should be reserved (i.e., 40th->44th bits).
    dst[start_pos] &= first_byte_mask;
    for (int i = start_pos + 1; i < 8; i++) {
        dst[i] = 0;
    }

    u8 original_first_byte = dst[start_pos];

    unsigned long long upper = 1 << (64 - len);
    assert(upper <= MAX_TARGET_NUMBER);
    printf("%lld Packets to Send.\n", upper);

    u8 bytes[8];
    union ull {
        unsigned long long val;
        u8 bytes[8];
    } i;

    i.val = 0;

    for (; i.val < upper; i.val++) {
        for (int j = 0; j < 8 && i.bytes[j] != 0; j++) {
            // Since IP Protocols are big endian-based, the byte order should be reversed.
            if (7 - j == start_pos) {
                dst[7 - j] = original_first_byte | i.bytes[j];
            } else {
                dst[7 - j] = i.bytes[j];
            }
        }
        randomizeIID(dst + 8);
        memcpy(targets[n_target++], dst, IPV6_ADDR_BYTES);
    }

    return;
}

int main() {
    char addr_str[MAX_IPV6_ADDR_LEN];
    generateScanningTargets("2001:1234:5678:9a00::/56");

    for (int i = 0; i < n_target; i++) {
        inet_ntop(AF_INET6, targets[i], addr_str, sizeof(addr_str));
        puts(addr_str);
    }
    return 0;
}