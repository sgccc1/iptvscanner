
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <iostream>
using namespace std;

char nicname = {0};

int iptvscan(unsigned int ip)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    int s;
    int err = -1;
    ip = htonl(ip);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1)
    {
        return -1;
    }

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = ip;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    err = setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
    if (err < 0)
    {
        close(s);
        return -1;
    }

    pcap_t *device = pcap_open_live(nicname, 65535, 1, 1, errBuf);
    if (!device)
    {
        cout << "error: pcap_open_live(): " << errBuf << endl;
        close(s);
        return -1;
    }

    char strfilter = "udp and host ";
    char *strip = strfilter + strlen("udp and host ");
    inet_ntop(AF_INET, &ip, strip, 16);

    struct bpf_program filter;
    pcap_compile(device, &filter, strfilter, 1, 0);
    pcap_setfilter(device, &filter);

    usleep(150000);
    struct pcap_pkthdr packet;
    const u_char *pktStr = pcap_next(device, &packet);
    if (pktStr)
    {
        struct udphdr *udphdr = NULL;
        udphdr = (struct udphdr *)(pktStr + 14 + 20);
#ifdef __linux
        printf("#EXTINF:-1,%s:%d\nrtp://%s:%d\n", strip, ntohs(udphdr->dest), strip, ntohs(udphdr->dest));
#elif __APPLE__
        printf("#EXTINF:-1,%s:%d\nrtp://%s:%d\n", strip, ntohs(udphdr->uh_dport), strip, ntohs(udphdr->uh_dport));
#endif
    }

    pcap_close(device);
    close(s);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        cout << "Usage: " << argv << " <network_interface> <multicast_ip>" << endl;
        return -1;
    }

    strcpy(nicname, argv);
    unsigned int ip;
    inet_pton(AF_INET, argv, &ip);

    cout << "#EXTM3U" << endl;
    iptvscan(ip);
    return 0;
}
