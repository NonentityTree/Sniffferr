#pragma once

#include "stdafx.h"
#include "pcap.h"

#pragma comment(lib,"wpcap.lib")   
#pragma comment(lib,"packet.lib")   
#pragma comment(lib,"ws2_32.lib")


pcap_if_t* getDevList();
pcap_if_t* chooseDev(pcap_if_t *alldevs, int inum);
pcap_t* openDev(pcap_if_t*d, pcap_if_t * alldevs);
bool setFilter(pcap_t *adhandle, pcap_if_t*d, pcap_if_t * alldevs, char *packet_filter, struct bpf_program *fcode);
void startCapture(pcap_t *adhandle, pcap_if_t*d, pcap_if_t * alldevs, pcap_dumper_t *dumpfile, char* filename);

pcap_t* load_data();

/* packet handler */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data);
void dispatcher_handler(u_char*, const struct pcap_pkthdr*, const u_char*);