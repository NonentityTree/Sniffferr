#pragma once
#include "pcap.h"
#include "protocol.h"

void Ethernet_analysis(const struct pcap_pkthdr *header, const u_char *pkt_data);

CString TCP_analysis(const struct ip_header *ih, const u_char *pkt_data);
CString UDP_analysis(const struct ip_header *ih, const u_char *pkt_data);
CString ICMP_analysis(const struct ip_header *ih, const u_char *pkt_data);

CString TCP_analysis(const struct ipv6_header *ih, const u_char *pkt_data);
CString UDP_analysis(const struct ipv6_header *ih, const u_char *pkt_data);
CString ICMPv6_analysis(const struct ipv6_header *ih, const u_char *pkt_data);

CString HTTP_analysis(const struct tcp_header *th, const u_char *pkt_data, u_int t_len);
CString DHCP_analysis(const struct udp_header *uh, const u_char *pkt_data);
CString DNS_analysis(const struct udp_header *uh, const u_char *pkt_data);
CString OICQ_analysis(const struct udp_header *uh, const u_char *pkt_data);
CString SSDP_analysis(const struct udp_header *uh, const u_char *pkt_data);

CString ARP_analysis(const struct pcap_pkthdr *header, const u_char *pkt_data);