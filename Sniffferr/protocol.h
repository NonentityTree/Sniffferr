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

/*4字节的IP地址*/
typedef struct ether_header
{
	u_char ether_dhost[6]; //目的Mac地址   
	u_char ether_shost[6]; //源Mac地址   
	u_short ether_type;   //协议类型   
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

/*IPv4首部*/
typedef struct ip_header {
	u_char ver_ihl;         //版本(4 bits) + 首部长度(4 bits)
	u_char tos;             //服务类型type of service(8 bits)
	u_short tlen;           //总长total length(16 bits)
	u_short identification; //标识
	u_short flags_fo;       //标志位flags(3 bits) + 段偏移量fragment offset(13 bits)
	u_char ttl;             //存活时间time to live
	u_char proto;           //协议protocol
	u_short crc;            //首部校验和header checksum
	ip_address saddr;       //源地址source address
	ip_address daddr;       //目的地址destination address
	u_int op_pad;           //选项 填充option padding
}ip_header;

/*IPv6首部*/
typedef struct ipv6_header {
	u_int ver_tc_fl;          //版本(4 bits)值为6 + 通信量类traffic class(8 bits) + 流标号flow label(20 bits)
	u_short plen;        //有效载荷长度payload length(16 bits), 只表示数据部分长度
	u_char nh;           //下一个首部next header(8 bits), 相当于IPv4协议字段
	u_char hl;           //跳数限制hop limit, 相当于IPv4的TLL
	ipv6_address saddr;  //源地址(128 bits)
	ipv6_address daddr;  //目的地址(128 bits)
	u_int ex;            //扩展首部extension
}ipv6_header;

/*UDP首部*/
typedef struct udp_header {
	u_short sport;   //源端口source port
	u_short dport;   //目的端口destination port
	u_short len;     //UDP数据包长度datagram length
	u_short crc;     //校验和
}udp_header;

/*TCP首部*/
typedef struct tcp_header {
	u_short sport;   //源端口source port(16 bits)
	u_short dport;   //目的端口destination port(16 bits)
	u_int sqnum;   //序号sequence number(32 bits)
	u_int acknum;  //确认号acknowledgment number(32 bits)
	u_short os_res_flags;  //数据偏移data offset(4 bits) + 保留reserved(6 bits) + 标志flag(6 bits)
	//u_char  URG;     //紧急指针有效
	//u_char  ACK;     //确认字段有效
	//u_char  PSH;     //推送数据
	//u_char  RST;     //连接复位
	//u_char  SYN;     //连接建立时序号同步
	//u_char  FIN;     //终止连接 
	u_short win_size;//窗口window size(16 bits)
	u_short crc;     //校验和
	u_short urg_ptr; //紧急指针urgent pointer(16 bits)
	u_int op;        //选项
}tcp_header;

/*ICMP首部*/
typedef struct icmp_header {
	u_char type;            //类型
	u_char code;            //代码
	u_short crc;            //校验和
	u_int identification;   //标识
}icmp_header;

/*ARP首部*/
typedef struct arp_header {
	u_short arp_hrd;  //硬件地址类型
	u_short arp_pro;  //协议地址类型
	u_char arp_hln;   //硬件地址长度
	u_char arp_pln;   //协议地址长度
	u_short arp_op;   //ARP/RARP操作
	u_char arp_eth_src[6]; //发送站硬件地址MAC
	ip_address saddr;     //发送站协议地址IP
	u_char arp_eth_dst[6]; //目的站硬件地址MAC
	ip_address daddr;     //目的站协议地址IP
}arp_header;

/*OICQ首部*/
typedef struct oicq_header {
	u_char flag;  //标识, 0x02
	u_short ver;  //版本号
	u_short com;  //命令
	u_short seq;  //序号
	u_int qqnum;  //qq号
}oicq_header;

/*DNS首部*/
typedef struct dns_header {
	u_short tid;  //会话标识transaction ID
	u_short flags;//标志
	u_short ques; //问题数
	u_short ans;  //回答 资源记录数answer RRs
	u_short auth; //授权 资源记录数authority RRs
	u_short addi; //附加 资源记录数additional RRs
	u_char dns_data;
}dns_header;

/*DHCP首部*/
typedef struct dhcp_header {
	u_char op;     //操作代码, client->server:1, server->client:2
	u_char htype;  //硬件类别, ethernet:1
	u_char hlen;   //硬件长度, ethernet:6
	u_char hops;   //跳数
	u_int xid;     //事务ID
	u_short secs;  //用户指定时间，开始地址获取和更新进行后的时间
	u_short flags;
	ip_address ciaddr;    //用户IP地址
	ip_address yiaddr;    //分配给客户的IP地址
	ip_address siaddr;    //用于bootstrap过程的IP地址
	ip_address giaddr;    //转发代理(网关)IP地址
	u_char chaddr[6]; //用户硬件地址
	u_int sname[16]; //服务器名称
	u_int file[32];  //启动文件名
	u_int opt[16];
}dhcp_header;

/*ICMPv6首部*/
typedef struct icmpv6_header {
	u_char type;            //类型
	u_char code;            //代码
	u_short crc;            //校验和
}icmpv6_header;
