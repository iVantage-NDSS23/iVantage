#include "common.h"

struct Config CFG;

void parseConfig() {
    char file_buf[FILE_BUFSIZE];

    char key[CONFIG_ATTR_MAXLEN];
    char val[CONFIG_ATTR_MAXLEN];

    FILE* fp = fopen("./config.ini", "r");
    if (fp == NULL) {
        perror("Config File Removed");
    }

    while (fgets(file_buf, FILE_BUFSIZE, fp) != NULL) {
        if (file_buf[0] == '[' || file_buf[0] == '\n') {
            continue;
        }

        if (sscanf(file_buf, "%s = %s", key, val) != 2) {
            perror("Config Format Error");
        }

        if (strcmp(key, "INTERFACE") == 0) {
            strcpy(CFG.interface, val);
        } else if (strcmp(key, "SRC_IPV6_ADDR") == 0) {
            strcpy(CFG.src_ipv6_addr, val);
        } else if (strcmp(key, "GATEWAY_MAC") == 0) {
            if (sscanf(val, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &CFG.gateway_mac[0],
                       &CFG.gateway_mac[1], &CFG.gateway_mac[2], &CFG.gateway_mac[3], &CFG.gateway_mac[4],
                       &CFG.gateway_mac[5]) != MAC_ADDR_BYTES) {
                perror("Gateway MAC Address Error");
            }
        } else if (strcmp(key, "ISAV_N") == 0) {
            CFG.iSAV_n = atoi(val);
        } else if (strcmp(key, "ISAV_M") == 0) {
            CFG.iSAV_m = atoi(val);
        } else if (strcmp(key, "RVPING_N") == 0) {
            CFG.RVPing_n = atoi(val);
        } else if (strcmp(key, "RVPING_M") == 0) {
            CFG.RVPing_n = atoi(val);
        } else {
            perror("Config Key Error");
        }
    }
    fclose(fp);
}