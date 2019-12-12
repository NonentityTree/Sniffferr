#pragma once
#include "stdafx.h"
#include "pcap.h"
#include "sniffer.h"
#include "parser.h"

pcap_if_t* getDevList()
{
	pcap_if_t *alldevs;   //所有网卡设备列表
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0;

	/* 获得设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
		//pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/*for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}*/

	return alldevs;
}

pcap_if_t* chooseDev(pcap_if_t *alldevs, int inum)
{
	pcap_if_t *d;         //当前选中网卡
	int i = 0;
	for (d = alldevs; d; d = d->next)
	{
		i++;
	}
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
	}

	/* 跳转到已选设备 */
	for (d = alldevs, i = 0; i < inum; d = d->next, i++);
	return d;
}

void freeDev(pcap_if_t * alldevs)
{
	/* 释放设备列表 */
	pcap_freealldevs(alldevs);
}

pcap_t * openDev(pcap_if_t * d, pcap_if_t *alldevs)
{
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* 打开适配器 */
	if ((adhandle = pcap_open(d->name,  // 设备名
		65536,     // 要捕捉的数据包的长度
				   // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
		1000,      // 读取超时时间
		NULL,      // 远程机器验证
		errbuf     // 错误缓冲池
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
	}
	/* 检查数据链路层，为了简单，只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
	}
	return adhandle;
}


bool setFilter(pcap_t *adhandle, pcap_if_t*d, pcap_if_t * alldevs, char *packet_filter, struct bpf_program *fcode)
{
	u_int netmask;
	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;
	//编译过滤器
	if (pcap_compile(adhandle, fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return false;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return false;
	}
	return true;
}

void startCapture(pcap_t * adhandle, pcap_if_t * d, pcap_if_t * alldevs, pcap_dumper_t *dumpfile, char * filename)
{
	dumpfile = pcap_dump_open(adhandle, filename);
	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 开始捕捉 */
	pcap_loop(adhandle, 30, packet_handler, (unsigned char *)dumpfile);
}

pcap_t* load_data()
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	//创建一个源字符串
	if (pcap_createsrcstr(source,  //源字符串
		PCAP_SRC_FILE,  //要打开的文件
		NULL,  //远程主机
		NULL,  //远程主机端口
		"packet.cap", //文件名
		errbuf) != 0) {
		fprintf(stderr, "\nError creating a source string\n");
	}

	//打开捕获文件
	if ((fp = pcap_open(source, //设备名
		65536,  //要捕捉的数据包部分,65535保证捕获到不同数据链路层上每个数据包全部内容
		PCAP_OPENFLAG_PROMISCUOUS, //混杂模式
		1000,  //读取超时时间
		NULL,  //errbuf
		errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the file %s. \n", source);
	}

	return fp;
}

/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	/* 保存数据包到堆文件 */
	pcap_dump(dumpfile, header, pkt_data);
}

void dispatcher_handler(u_char *temp, const pcap_pkthdr *header, const u_char *pkt_data)
{
	//Ethernet_analysis(header, pkt_data);
}

