#pragma once
#include "stdafx.h"
#include "parser.h"

void Ethernet_analysis(const struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* ��ӡ���ݰ���ʱ����ͳ��� */
	printf("%s.%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

	/* ���IP���ݰ�ͷ����λ�� */
	ip_header *ih = (ip_header *)(pkt_data +
		14); //��̫��ͷ������
#define LINE_LEN 16
	char temp[LINE_LEN + 1];
	//�����
	for (u_int i = 0; i < header->caplen; ++i)
	{
		printf("%.2x ", pkt_data[i]);
		if (isgraph(pkt_data[i]) || pkt_data[i] == ' ')
			temp[i % LINE_LEN] = pkt_data[i];
		else
			temp[i % LINE_LEN] = '.';

		if (i % LINE_LEN == 15)
		{
			temp[16] = '\0';
			printf("        ");
			printf("%s", temp);
			printf("\n");
			memset(temp, 0, LINE_LEN);
		}
	}
	printf("\n");

	ether_header * eheader = (ether_header*)(pkt_data);
	//��̫��Դ->Ŀ�ĵ�ַ
	u_char* mac_shost = eheader->ether_shost;
	u_char* mac_dhost = eheader->ether_dhost;
	printf("Data link layer: Ethernet %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac_shost,
		*(mac_shost + 1),
		*(mac_shost + 2),
		*(mac_shost + 3),
		*(mac_shost + 4),
		*(mac_shost + 5),
		*mac_dhost,
		*(mac_dhost + 1),
		*(mac_dhost + 2),
		*(mac_dhost + 3),
		*(mac_dhost + 4),
		*(mac_dhost + 5));


	switch (ntohs(eheader->ether_type)) {
	case PROTOCOL_IPv4: {
		printf("Network layer: IPv4\n");
		/* ���IP���ݰ�ͷ����λ�� */
		ip_header *ih = (ip_header *)(pkt_data +
			14); //��̫��ͷ������

		u_char protocol = ih->proto;
		switch (protocol) {
		case PROTOCOL_TCP:
			TCP_analysis(ih, pkt_data + 14);
			break;
		case PROTOCOL_ICMP:
			ICMP_analysis(ih, pkt_data + 14);
			break;
		case PROTOCOL_UDP:
			UDP_analysis(ih, pkt_data + 14);
			break;
		default:
			printf("IPv4 Transport layer protocol not supportive yet.\n");
			break;
		}
		break;
	}

	case PROTOCOL_ARP:
		ARP_analysis(header, pkt_data);
		break;
	case PROTOCOL_IPv6: {
		printf("Network layer: IPv6\n");
		/* ���IP���ݰ�ͷ����λ�� */
		ipv6_header *ih6 = (ipv6_header *)(pkt_data +
			14); //��̫��ͷ������
		u_char protocol = ih6->nh;
		switch (protocol) {
		case PROTOCOL_TCP:
			TCP_analysis(ih6, pkt_data + 14);
			break;
		case PROTOCOL_ICMPv6:
			ICMPv6_analysis(ih6, pkt_data + 14);
			break;
		case PROTOCOL_UDP:
			UDP_analysis(ih6, pkt_data + 14);
			break;
		default:
			printf("IPv6 Transport layer protocol not supportive yet.\n");
			break;
		}
		break;
	}

	default:
		printf("Network layer protocol not supportive yet.\n");
	}
	printf("\n**********************************************\n\n");

}

CString UDP_analysis(const struct ip_header *ih, const u_char *pkt_data) {
	u_int ip_len;
	u_short sport, dport;
	CString str;
	/* ���UDP�ײ���λ�� */
	ip_len = (ih->ver_ihl & 0xf) * 4;//ip�ײ�����
	udp_header *uh = (udp_header *)((u_char*)ih + ip_len);
	/* �������ֽ�����ת���������ֽ����� */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);
	u_short udp_len = ntohs(uh->len);
	bool udp = true;
	/* ��ӡIP��ַ��UDP�˿� */
	str.Format("Transport layer: UDP %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
	return str;
}

CString TCP_analysis(const struct ip_header *ih, const u_char *pkt_data) {
	u_int ip_len;
	u_short sport, dport;
	CString str;
	/* ���TCP�ײ���λ�� */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	tcp_header *th = (tcp_header *)((u_char*)ih + ip_len);
	sport = ntohs(th->sport);
	dport = ntohs(th->dport);
	/* �������ֽ�����ת���������ֽ����� */
	sport = ntohs(th->sport);
	dport = ntohs(th->dport);
	/* ��ӡIP��ַ��TCP�˿� */
	str.Format("Transport layer: TCP %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
	return str;
}

CString HTTP_analysis(const struct tcp_header *th, const u_char *pkt_data, u_int t_len) {
	char *ip_pkt_data = (char*)pkt_data;
	bool find_http = false;
	CString str;
	char buffer[BUFFER_MAX_LENGTH];
	int bufsize = 0;
	u_short sport = ntohs(th->sport);
	u_short dport = ntohs(th->dport);
	for (u_int i = 20; i < t_len; i++) {
		//GET����
		if (!find_http && i + 3 < t_len && (strncmp(ip_pkt_data + i, "GET", strlen("GET")) == 0))
			find_http = true;
		//POST����
		if (!find_http && i + 4 < t_len && (strncmp(ip_pkt_data + i, "POST", strlen("POST")) == 0))
			find_http = true;
		//��Ӧ
		if (!find_http && i + 8 < t_len && (strncmp(ip_pkt_data + i, "HTTP/1.1", strlen("HTTP/1.1")) == 0))
			find_http = true;

		if (find_http)
		{
			buffer[bufsize] = ip_pkt_data[i];
			bufsize++;
		}
	}

	if (find_http) {
		buffer[bufsize] = '\0';
		str.Format("Application layer: HTTP %s", buffer);
		return str;
	}
	else {
		return NULL;
	}
		
}

CString DHCP_analysis(const udp_header * uh, const u_char * pkt_data)
{
	CString str;
	dhcp_header* dhh = (dhcp_header*)((u_char*)uh + 8);//udp�ײ�8�ֽ�
	str.Format("Application layer: DHCP\n");
	if (dhh->op == 0x02) {
		printf("Yiaddr: %d.%d.%d.%d\n",
			dhh->yiaddr.byte1,
			dhh->yiaddr.byte2,
			dhh->yiaddr.byte3,
			dhh->yiaddr.byte4);
	}
	return str;
	
}

CString DNS_analysis(const udp_header * uh, const u_char * pkt_data)
{
	CString str;
	dns_header* dh = (dns_header*)((u_char*)uh + 8);//udp�ײ�8�ֽ�
	str.Format("Application layer: DNS TID: %x, Flags: %x Query: %x Answer RRs: %d, Authority: %x",
		ntohs(dh->tid), ntohs(dh->flags), ntohs(dh->ques), ntohs(dh->ans), ntohs(dh->auth));
	return str;
}

CString OICQ_analysis(const udp_header * uh, const u_char * pkt_data)
{
	CString str;
	oicq_header *oh = (oicq_header*)((u_char*)uh + 8); //udp�ײ�8�ֽ�
	if (oh->flag == 0x02) {//��ʶ
		str.Format("Application layer: OICQ\n");
	}
	return str;
	
		

}

CString SSDP_analysis(const udp_header * uh, const u_char * pkt_data)
{
	CString str;
	
	str.Format("Application layer: SSDP\n");
	return str;
}

CString ARP_analysis(const struct pcap_pkthdr *header, const u_char *pkt_data) {
	CString str;
	arp_header *ah = (arp_header *)(pkt_data +
		14); //��̫��ͷ������
	str.Format("Network layer: ARP\n");
	return str;
}

CString ICMP_analysis(const struct ip_header *ih, const u_char *pkt_data) {
	/* ���ICMP�ײ���λ�� */
	CString str;
	u_int ip_len = (ih->ver_ihl & 0xf) * 4;
	icmp_header *ich = (icmp_header *)((u_char*)ih + ip_len);
	str.Format("Tranport layer: ICMP Type: %d Code: %d", ich->type, ich->code);
	return str;
}

CString TCP_analysis(const ipv6_header * ih, const u_char * pkt_data)
{
	CString str;
	tcp_header *th = (tcp_header *)((u_char*)ih + 40);//IPv6�ײ��̶�����40 bits
	/* �������ֽ�����ת���������ֽ����� */
	u_short sport = ntohs(th->sport);
	u_short dport = ntohs(th->dport);
	/* ��ӡIP��ַ��TCP�˿� */
	str.Format("Tranport layer: TCP %x.%x.%x.%x.%x.%x.%x.%x:%d -> %x.%x.%x.%x.%x.%x.%x.%x:%d\n",
		ntohs(ih->saddr.addr1),
		ntohs(ih->saddr.addr2),
		ntohs(ih->saddr.addr3),
		ntohs(ih->saddr.addr4),
		ntohs(ih->saddr.addr5),
		ntohs(ih->saddr.addr6),
		ntohs(ih->saddr.addr7),
		ntohs(ih->saddr.addr8),
		sport,
		ntohs(ih->daddr.addr1),
		ntohs(ih->daddr.addr2),
		ntohs(ih->daddr.addr3),
		ntohs(ih->daddr.addr4),
		ntohs(ih->daddr.addr5),
		ntohs(ih->daddr.addr6),
		ntohs(ih->daddr.addr7),
		ntohs(ih->daddr.addr8),
		dport);
	return str;
}


CString UDP_analysis(const ipv6_header * ih, const u_char * pkt_data)
{
	CString str;
	udp_header *uh = (udp_header *)((u_char*)ih + 40);//IPv6�ײ��̶�����40 bits
	/* �������ֽ�����ת���������ֽ����� */
	u_short sport = ntohs(uh->sport);
	u_short dport = ntohs(uh->dport);
	/* ��ӡIP��ַ��UDP�˿� */
	str.Format("Transport layer: UDP %x.%x.%x.%x.%x.%x.%x.%x:%d -> %x.%x.%x.%x.%x.%x.%x.%x:%d\n",
		ntohs(ih->saddr.addr1),
		ntohs(ih->saddr.addr2),
		ntohs(ih->saddr.addr3),
		ntohs(ih->saddr.addr4),
		ntohs(ih->saddr.addr5),
		ntohs(ih->saddr.addr6),
		ntohs(ih->saddr.addr7),
		ntohs(ih->saddr.addr8),
		sport,
		ntohs(ih->daddr.addr1),
		ntohs(ih->daddr.addr2),
		ntohs(ih->daddr.addr3),
		ntohs(ih->daddr.addr4),
		ntohs(ih->daddr.addr5),
		ntohs(ih->daddr.addr6),
		ntohs(ih->daddr.addr7),
		ntohs(ih->daddr.addr8),
		dport);
	return str;
}

CString ICMPv6_analysis(const ipv6_header * ih, const u_char * pkt_data)
{
	CString str;
	icmpv6_header* ich = (icmpv6_header*)((u_char*)ih + 40);//ipv6�ײ�����
	str.Format("Application layer: ICMPv6 Type: %d Code: %d", ich->type, ich->code);
	return str;
}

