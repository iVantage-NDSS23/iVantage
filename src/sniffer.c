#include "sniffer.h"

char errBuf[PCAP_ERRBUF_SIZE];
pcap_t* sniffer;
struct bpf_program filter;
pthread_t sniff_thread;

void setSniffer(const char* interface) {
    sniffer = pcap_open_live(interface, 1514, 1, 0, errBuf);
    if (!sniffer) {
        perror("error: pcap_open_live()");
        exit(1);
    }
    pcap_set_buffer_size(sniffer, 1024 * KILO);
}

void setSnifferFilter(const char* my_filter) {
    pcap_compile(sniffer, &filter, my_filter, 1, 0);
    pcap_setfilter(sniffer, &filter);
}

void processPacket(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct SniffLog* ptr   = (struct SniffLog*) arg;
    ptr->tv[ptr->captured] = pkthdr->ts;
    (ptr->captured)++;
    return;
}

void sigHandlerBreakLoop(int arg) {
    pcap_breakloop(sniffer);
}

void* doSniff(void* ptr) {
    struct sigaction act;
    sigaddset(&act.sa_mask, SIGUSR1);
    act.sa_handler = sigHandlerBreakLoop;
    act.sa_flags   = 0;
    sigaction(SIGUSR1, &act, NULL);
    pcap_loop(sniffer, -1, processPacket, (u_char*) ptr);
    return (void*) (NULL);
}

void* doSniffOne(void* ptr) {
    struct sigaction act;
    sigaddset(&act.sa_mask, SIGUSR1);
    act.sa_handler = sigHandlerBreakLoop;
    act.sa_flags   = 0;
    sigaction(SIGUSR1, &act, NULL);
    pcap_loop(sniffer, 1, processPacket, (u_char*) ptr);
    return (void*) (NULL);
}

void startSniff(struct SniffLog* ptr) {
    memset(ptr, 0, sizeof(struct SniffLog));
    int ret = pthread_create(&sniff_thread, NULL, doSniff, (void*) ptr);
    if (ret < 0) {
        perror("Failed to Create Sniff Thread.");
        exit(1);
    }
}

void startSniffOne(struct SniffLog* ptr) {
    memset(ptr, 0, sizeof(struct SniffLog));
    int ret = pthread_create(&sniff_thread, NULL, doSniffOne, (void*) ptr);
    if (ret < 0) {
        perror("Failed to Create Sniff Thread.");
        exit(1);
    }
}

void stopSniff(unsigned int wait_usec) {
    struct timeval upper_tv;
    struct timeval current_tv;
    gettimeofday(&upper_tv, NULL);
    upper_tv.tv_usec += (long) wait_usec;
    while (upper_tv.tv_usec > MILL) {
        upper_tv.tv_usec -= MILL;
        upper_tv.tv_sec++;
    }

    while (pthread_kill(sniff_thread, 0) != ESRCH) {
        gettimeofday(&current_tv, NULL);
        if (current_tv.tv_sec > upper_tv.tv_sec ||
            (current_tv.tv_sec == upper_tv.tv_sec &&
             current_tv.tv_usec >= upper_tv.tv_usec)) {
            int rt = pthread_kill(sniff_thread, SIGUSR1);
            pthread_join(sniff_thread, NULL);
            break;
        }
        usleep(100 * KILO);
    }
}