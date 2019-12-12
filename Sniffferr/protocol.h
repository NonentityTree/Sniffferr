#pragma once
#include "stdafx.h"

#define PROTOCOL_IPv4   0x0800
#define PROTOCOL_IPv6   0x86DD
#define PROTOCOL_ARP    0x0806

#define PROTOCOL_TCP    0x06
#define PROTOCOL_UDP    0x11 //17
#define PROTOCOL_ICMP   0x01
#define PROTOCOL_ICMPv6 0x3a //58
#define PROTOCOL_IGMP   0x02

#define PROTOCOL_HTTP 80
#define PROTOCOL_DNS  53
#define PROTOCOL_SSDP 1900
#define PROTOCOL_OICQ 8000
#define PROTOCOL_DHCP_CLIENT 67
#define PROTOCOL_DHCP_SERVER 68

#define BUFFER_MAX_LENGTH 65535


typedef struct raw_data {
	const struct pcap_pkthdr *header;
	const u_char *pkt_data;
}raw_data;

/*4�ֽڵ�IP��ַ*/
typedef struct ether_header
{
	u_char ether_dhost[6]; //Ŀ��Mac��ַ   
	u_char ether_shost[6]; //ԴMac��ַ   
	u_short ether_type;   //Э������   
}ether_header;

typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ipv6_address {
	u_short addr1;
	u_short addr2;
	u_short addr3;
	u_short addr4;
	u_short addr5;
	u_short addr6;
	u_short addr7;
	u_short addr8;
}ipv6_address;

/*IPv4�ײ�*/
typedef struct ip_header {
	u_char ver_ihl;         //�汾(4 bits) + �ײ�����(4 bits)
	u_char tos;             //��������type of service(8 bits)
	u_short tlen;           //�ܳ�total length(16 bits)
	u_short identification; //��ʶ
	u_short flags_fo;       //��־λflags(3 bits) + ��ƫ����fragment offset(13 bits)
	u_char ttl;             //���ʱ��time to live
	u_char proto;           //Э��protocol
	u_short crc;            //�ײ�У���header checksum
	ip_address saddr;       //Դ��ַsource address
	ip_address daddr;       //Ŀ�ĵ�ַdestination address
	u_int op_pad;           //ѡ�� ���option padding
}ip_header;

/*IPv6�ײ�*/
typedef struct ipv6_header {
	u_int ver_tc_fl;          //�汾(4 bits)ֵΪ6 + ͨ������traffic class(8 bits) + �����flow label(20 bits)
	u_short plen;        //��Ч�غɳ���payload length(16 bits), ֻ��ʾ���ݲ��ֳ���
	u_char nh;           //��һ���ײ�next header(8 bits), �൱��IPv4Э���ֶ�
	u_char hl;           //��������hop limit, �൱��IPv4��TLL
	ipv6_address saddr;  //Դ��ַ(128 bits)
	ipv6_address daddr;  //Ŀ�ĵ�ַ(128 bits)
	u_int ex;            //��չ�ײ�extension
}ipv6_header;

/*UDP�ײ�*/
typedef struct udp_header {
	u_short sport;   //Դ�˿�source port
	u_short dport;   //Ŀ�Ķ˿�destination port
	u_short len;     //UDP���ݰ�����datagram length
	u_short crc;     //У���
}udp_header;

/*TCP�ײ�*/
typedef struct tcp_header {
	u_short sport;   //Դ�˿�source port(16 bits)
	u_short dport;   //Ŀ�Ķ˿�destination port(16 bits)
	u_int sqnum;   //���sequence number(32 bits)
	u_int acknum;  //ȷ�Ϻ�acknowledgment number(32 bits)
	u_short os_res_flags;  //����ƫ��data offset(4 bits) + ����reserved(6 bits) + ��־flag(6 bits)
	//u_char  URG;     //����ָ����Ч
	//u_char  ACK;     //ȷ���ֶ���Ч
	//u_char  PSH;     //��������
	//u_char  RST;     //���Ӹ�λ
	//u_char  SYN;     //���ӽ���ʱ���ͬ��
	//u_char  FIN;     //��ֹ���� 
	u_short win_size;//����window size(16 bits)
	u_short crc;     //У���
	u_short urg_ptr; //����ָ��urgent pointer(16 bits)
	u_int op;        //ѡ��
}tcp_header;

/*ICMP�ײ�*/
typedef struct icmp_header {
	u_char type;            //����
	u_char code;            //����
	u_short crc;            //У���
	u_int identification;   //��ʶ
}icmp_header;

/*ARP�ײ�*/
typedef struct arp_header {
	u_short arp_hrd;  //Ӳ����ַ����
	u_short arp_pro;  //Э���ַ����
	u_char arp_hln;   //Ӳ����ַ����
	u_char arp_pln;   //Э���ַ����
	u_short arp_op;   //ARP/RARP����
	u_char arp_eth_src[6]; //����վӲ����ַMAC
	ip_address saddr;     //����վЭ���ַIP
	u_char arp_eth_dst[6]; //Ŀ��վӲ����ַMAC
	ip_address daddr;     //Ŀ��վЭ���ַIP
}arp_header;

/*OICQ�ײ�*/
typedef struct oicq_header {
	u_char flag;  //��ʶ, 0x02
	u_short ver;  //�汾��
	u_short com;  //����
	u_short seq;  //���
	u_int qqnum;  //qq��
}oicq_header;

/*DNS�ײ�*/
typedef struct dns_header {
	u_short tid;  //�Ự��ʶtransaction ID
	u_short flags;//��־
	u_short ques; //������
	u_short ans;  //�ش� ��Դ��¼��answer RRs
	u_short auth; //��Ȩ ��Դ��¼��authority RRs
	u_short addi; //���� ��Դ��¼��additional RRs
	u_char dns_data;
}dns_header;

/*DHCP�ײ�*/
typedef struct dhcp_header {
	u_char op;     //��������, client->server:1, server->client:2
	u_char htype;  //Ӳ�����, ethernet:1
	u_char hlen;   //Ӳ������, ethernet:6
	u_char hops;   //����
	u_int xid;     //����ID
	u_short secs;  //�û�ָ��ʱ�䣬��ʼ��ַ��ȡ�͸��½��к��ʱ��
	u_short flags;
	ip_address ciaddr;    //�û�IP��ַ
	ip_address yiaddr;    //������ͻ���IP��ַ
	ip_address siaddr;    //����bootstrap���̵�IP��ַ
	ip_address giaddr;    //ת������(����)IP��ַ
	u_char chaddr[6]; //�û�Ӳ����ַ
	u_int sname[16]; //����������
	u_int file[32];  //�����ļ���
	u_int opt[16];
}dhcp_header;

/*ICMPv6�ײ�*/
typedef struct icmpv6_header {
	u_char type;            //����
	u_char code;            //����
	u_short crc;            //У���
}icmpv6_header;
