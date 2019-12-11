#pragma once
#include "stdafx.h"
#include "pcap.h"
#include "sniffer.h"
#include "parser.h"

pcap_if_t* getDevList()
{
	pcap_if_t *alldevs;   //���������豸�б�
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0;

	/* ����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
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
	pcap_if_t *d;         //��ǰѡ������
	int i = 0;
	for (d = alldevs; d; d = d->next)
	{
		i++;
	}
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
	}

	/* ��ת����ѡ�豸 */
	for (d = alldevs, i = 0; i < inum; d = d->next, i++);
	return d;
}

void freeDev(pcap_if_t * alldevs)
{
	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);
}

pcap_t * openDev(pcap_if_t * d, pcap_if_t *alldevs)
{
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* �������� */
	if ((adhandle = pcap_open(d->name,  // �豸��
		65536,     // Ҫ��׽�����ݰ��ĳ���
				   // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,         // ����ģʽ
		1000,      // ��ȡ��ʱʱ��
		NULL,      // Զ�̻�����֤
		errbuf     // ���󻺳��
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
	}
	/* ���������·�㣬Ϊ�˼򵥣�ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
	}
	return adhandle;
}


bool setFilter(pcap_t *adhandle, pcap_if_t*d, pcap_if_t * alldevs, char *packet_filter, struct bpf_program *fcode)
{
	u_int netmask;
	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;
	//���������
	if (pcap_compile(adhandle, fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return false;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return false;
	}
	return true;
}

void startCapture(pcap_t * adhandle, pcap_if_t * d, pcap_if_t * alldevs, pcap_dumper_t *dumpfile, char * filename)
{
	dumpfile = pcap_dump_open(adhandle, filename);
	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	/* ��ʼ��׽ */
	pcap_loop(adhandle, 30, packet_handler, (unsigned char *)dumpfile);
}

pcap_t* load_data()
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	//����һ��Դ�ַ���
	if (pcap_createsrcstr(source,  //Դ�ַ���
		PCAP_SRC_FILE,  //Ҫ�򿪵��ļ�
		NULL,  //Զ������
		NULL,  //Զ�������˿�
		"packet.cap", //�ļ���
		errbuf) != 0) {
		fprintf(stderr, "\nError creating a source string\n");
	}

	//�򿪲����ļ�
	if ((fp = pcap_open(source, //�豸��
		65536,  //Ҫ��׽�����ݰ�����,65535��֤���񵽲�ͬ������·����ÿ�����ݰ�ȫ������
		PCAP_OPENFLAG_PROMISCUOUS, //����ģʽ
		1000,  //��ȡ��ʱʱ��
		NULL,  //errbuf
		errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the file %s. \n", source);
	}

	return fp;
}

/* �ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������ */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	/* �������ݰ������ļ� */
	pcap_dump(dumpfile, header, pkt_data);
}

void dispatcher_handler(u_char *temp, const pcap_pkthdr *header, const u_char *pkt_data)
{
	//Ethernet_analysis(header, pkt_data);
}

