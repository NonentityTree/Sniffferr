// PacketDlg.cpp: ʵ���ļ�
//

#include "stdafx.h"
#include "Sniffferr.h"
#include "PacketDlg.h"
#include "SniffferrDlg.h"
#include "afxdialogex.h"
#include "sniffer.h"
#include "parser.h"
#include <thread>
#include <ctime>
#include <string>
#include <mutex>
#include <Windows.h>
using std::thread;
using std::to_string;
using std::string;

bool flag = false;
std::mutex mutex;

// PacketDlg �Ի���

IMPLEMENT_DYNAMIC(PacketDlg, CDialogEx)

PacketDlg::PacketDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PACKET_DIALOG, pParent)
{
	
}

PacketDlg::~PacketDlg()
{
}

void PacketDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_FILTER_COMBO, filter);
	DDX_Control(pDX, IDC_PACKET_LIST, packetList);
	DDX_Control(pDX, IDC_INFORMATION_LIST, Information);
}



BEGIN_MESSAGE_MAP(PacketDlg, CDialogEx)

	ON_CBN_SELCHANGE(IDC_FILTER_COMBO, &PacketDlg::OnCbnSelchangeFilterCombo)
	ON_BN_CLICKED(IDSTART, &PacketDlg::OnBnClickedStart)
	ON_BN_CLICKED(IDPAUSE, &PacketDlg::OnBnClickedPause)
	ON_LBN_SELCHANGE(IDC_PACKET_LIST, &PacketDlg::OnLbnSelchangePacketList)
	ON_MESSAGE(UPDATEPACKET, &PacketDlg::OnUpdatePacket)
	ON_BN_CLICKED(IDC_STOP, &PacketDlg::OnBnClickedStop)
	ON_BN_CLICKED(IDC_RETURN, &PacketDlg::OnBnClickedReturn)
END_MESSAGE_MAP()


// PacketDlg ��Ϣ�������




int start(pcap_dumper_t * dumpfile, pcap_t * adhandle, HWND hWnd)
{
	while (flag) {
		pcap_pkthdr* header = NULL;
		const u_char* pkt_data = NULL;
		int pkt = pcap_next_ex(adhandle, &header, &pkt_data);
		if (pkt > 0) {
			pcap_dump((unsigned char *)dumpfile, header, pkt_data);
			parseNshow(adhandle, header, pkt_data, hWnd);
		}
		/*thread t1(capture, dumpfile, adhandle, std::ref(header), std::cref(pkt_data));
		t1.join();
		thread t2(parseNshow, adhandle, std::ref(header), std::cref(pkt_data), hWnd);
		t2.detach();*/

	}
	return 0;

}

int capture(pcap_dumper_t *dumpfile, pcap_t *adhandle, struct pcap_pkthdr *header, const u_char *pkt_data)
{

	/* ��ʼ��׽ */
	pcap_loop(adhandle, 1, packet_handler, (unsigned char *)dumpfile);
	//pcap_next_ex(adhandle, &header, &pkt_data);
	//pcap_dump((unsigned char *)dumpfile, header, pkt_data);
	return 0;
}



UINT PacketDlg::MyThreadFunction(LPVOID pParam)
{
	//�߳���ں���������ʵ��
	PacketDlg* dlg = (PacketDlg*)pParam;
	int count = 0;
	while (!dlg->flag_myThread) {
		int pkt = pcap_next_ex(dlg->adhandle, &dlg->header, &dlg->pkt_data);

		if (pkt > 0) {
			pcap_dump((unsigned char *)dlg->dumpfile, dlg->header, dlg->pkt_data);
			parseNshow(dlg->adhandle, dlg->header, dlg->pkt_data, dlg->m_hWnd);
			count++;
			dlg->SetDlgItemInt(IDC_NUMBER, count, false);
		}
		Sleep(100);
	}

	dlg->p_myThread = NULL;//�߳̽���ע�����̲߳�����
	return 0;
}

void PacketDlg::OnCbnSelchangeFilterCombo()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

}




void PacketDlg::OnBnClickedStart()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if (dumpfile == NULL) {
		filename = "packet.cap";          //�ļ���
		dumpfile = pcap_dump_open(adhandle, filename);
	}
	CString str;   //���˹���
	struct bpf_program fcode;            //BPF���˻���
	int nIndex = filter.GetCurSel();
	filter.GetLBText(nIndex, str);
	char* packet_filter = str.GetBuffer();
	if (str != "none") {
		setFilter(adhandle, d, alldevs, packet_filter, &fcode);
	}
	/*mutex.lock();
	flag = true;
	mutex.unlock();
	thread t(start, dumpfile, adhandle, this->m_hWnd);
	t.detach();*/
	if (p_myThread == NULL) //�����߳������ɹ�
	{    //�����������߳�
		packetList.ResetContent();
		p_myThread = AfxBeginThread(MyThreadFunction, (LPVOID)this);//this�����߳���ں����Ĳ���pParam
		flag_myThread = FALSE;
	}
	else
	{
		p_myThread->ResumeThread();//����
	}
}


void PacketDlg::OnBnClickedPause()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	/*mutex.lock();
	flag = false;
	mutex.unlock();*/
	if (p_myThread == NULL)//�����߳������ɹ�
	{
		AfxMessageBox(_T("�̲߳�����"));
	}
	else
	{
		p_myThread->SuspendThread();//��ͣ������
	}
}

int parseNshow(pcap_t *adhandle, struct pcap_pkthdr *header, const u_char *pkt_data, HWND hWnd)
{
	time_t local_tv_sec;
	struct tm ltime;
	char timestr[16];
	CString str;
	/* ��ȡ���ݰ� */
	/*pcap_t* fp = load_data();
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {*/

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	ether_header * eheader = (ether_header*)(pkt_data);
	switch (ntohs(eheader->ether_type)) {
	case PROTOCOL_IPv4: {
		ip_header *ih = (ip_header *)(pkt_data +
			14); //��̫��ͷ������
		//IPԴ->Ŀ�ĵ�ַ
		str.Format("%s IPv4: %d.%d.%d.%d -> %d.%d.%d.%d",
			timestr,
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4
		);

		break;
	}
	case PROTOCOL_IPv6: {
		ipv6_header *ih = (ipv6_header *)(pkt_data +
			14); //��̫��ͷ������
		//IPԴ->Ŀ�ĵ�ַ
		str.Format("%s IPv6 %x.%x.%x.%x.%x.%x.%x.%x -> %x.%x.%x.%x.%x.%x.%x.%x",
			timestr,
			ntohs(ih->saddr.addr1),
			ntohs(ih->saddr.addr2),
			ntohs(ih->saddr.addr3),
			ntohs(ih->saddr.addr4),
			ntohs(ih->saddr.addr5),
			ntohs(ih->saddr.addr6),
			ntohs(ih->saddr.addr7),
			ntohs(ih->saddr.addr8),
			ntohs(ih->daddr.addr1),
			ntohs(ih->daddr.addr2),
			ntohs(ih->daddr.addr3),
			ntohs(ih->daddr.addr4),
			ntohs(ih->daddr.addr5),
			ntohs(ih->daddr.addr6),
			ntohs(ih->daddr.addr7),
			ntohs(ih->daddr.addr8)
		);

		break;
	}
	case PROTOCOL_ARP: {
		u_char* mac_shost = eheader->ether_shost;
		u_char* mac_dhost = eheader->ether_dhost;
		str.Format("%s ARP %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
			timestr,
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

		break;
	}
	default:
		str += ("   Network layer protocol not supportive yet");
	}
	SendMessage(hWnd, UPDATEPACKET, (WPARAM)(&str), 0);
	return 0;
}






void PacketDlg::OnLbnSelchangePacketList()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	Information.ResetContent();
	CString str;
	int nIndex = packetList.GetCurSel();
	fp = load_data();
	for (int i = 0; i < nIndex + 1; i++) {
		pcap_next_ex(fp, &header, &pkt_data);
	}

	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* ��ӡ���ݰ���ʱ����ͳ��� */
	str.Format("Time: %s.%.6d", timestr, header->ts.tv_usec);
	Information.AddString(str);
	str.Format("Length: %d", header->len);
	Information.AddString(str);

	/* ���IP���ݰ�ͷ����λ�� */
	ip_header *ih = (ip_header *)(pkt_data +
		14); //��̫��ͷ������
	ether_header * eheader = (ether_header*)(pkt_data);
	//��̫��Դ->Ŀ�ĵ�ַ
	u_char* mac_shost = eheader->ether_shost;
	u_char* mac_dhost = eheader->ether_dhost;
	str.Format("Data link layer: Ethernet  %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
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
	Information.AddString(str);

	switch (ntohs(eheader->ether_type)) {
	case PROTOCOL_IPv4: {
		str.Format("Network layer: IPv4\n");
		Information.AddString(str);
		/* ���IP���ݰ�ͷ����λ�� */
		ip_header *ih = (ip_header *)(pkt_data +
			14); //��̫��ͷ������
		u_int ip_len;
		u_short sport, dport;
		/* ���UDP�ײ���λ�� */
		ip_len = (ih->ver_ihl & 0xf) * 4;//ip�ײ�����

		u_char protocol = ih->proto;
		switch (protocol) {
		case PROTOCOL_TCP: {
			str = TCP_analysis(ih, pkt_data + 14);
			Information.AddString(str);

			tcp_header *th = (tcp_header *)((u_char*)ih + ip_len);
			sport = ntohs(th->sport);
			dport = ntohs(th->dport);
			if (sport == PROTOCOL_HTTP || dport == PROTOCOL_HTTP) {
				char *ip_pkt_data = (char*)pkt_data;
				bool find_http = false;
				char buffer[BUFFER_MAX_LENGTH];
				int bufsize = 0;
				u_short t_len = ih->tlen;
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
					Information.AddString("Application layer: HTTP");
					str.Format("%s", buffer);
					Information.AddString(str);
				}
			}
			break;
		}

		case PROTOCOL_ICMP: {
			str = ICMP_analysis(ih, pkt_data + 14);
			Information.AddString(str);
			break;
		}

		case PROTOCOL_UDP: {
			str = UDP_analysis(ih, pkt_data + 14);
			Information.AddString(str);

			udp_header *uh = (udp_header *)((u_char*)ih + ip_len);
			sport = ntohs(uh->sport);
			dport = ntohs(uh->dport);
			if ((sport == PROTOCOL_DHCP_CLIENT && dport == PROTOCOL_DHCP_SERVER
				|| (dport == PROTOCOL_DHCP_CLIENT && sport == PROTOCOL_DHCP_SERVER))) {
				dhcp_header* dhh = (dhcp_header*)((u_char*)uh + 8);//udp�ײ�8�ֽ�
				str.Format("Application layer: DHCP TID: %x", ntohs(dhh->xid));
				Information.AddString(str);
				if (dhh->op == 0x01) {
					Information.AddString("Boot Request");
				}
				else if (dhh->op == 0x02) {
					Information.AddString("Boot Reply");
				}
				str.Format("Client IP Address: %d.%d.%d.%d",
					dhh->ciaddr.byte1,
					dhh->ciaddr.byte2,
					dhh->ciaddr.byte3,
					dhh->ciaddr.byte4);
				Information.AddString(str);
				str.Format("Your (client) IP Address: %d.%d.%d.%d",
					dhh->yiaddr.byte1,
					dhh->yiaddr.byte2,
					dhh->yiaddr.byte3,
					dhh->yiaddr.byte4);
				Information.AddString(str);
				str.Format("Next Server IP Address: %d.%d.%d.%d",
					dhh->siaddr.byte1,
					dhh->siaddr.byte2,
					dhh->siaddr.byte3,
					dhh->siaddr.byte4);
				Information.AddString(str);
				str.Format("Relay Agent IP Address: %d.%d.%d.%d",
					dhh->giaddr.byte1,
					dhh->giaddr.byte2,
					dhh->giaddr.byte3,
					dhh->giaddr.byte4);
				Information.AddString(str);
			}
			else if (sport == PROTOCOL_DNS || dport == PROTOCOL_DNS) {
				/*str = DNS_analysis(uh, pkt_data + ip_len);
				Information.AddString(str);*/
				dns_header* dh = (dns_header*)((u_char*)uh + 8);//udp�ײ�8�ֽ�
				Information.AddString("Application layer: DNS");
				str.Format("TID: %x, Flags: %x", ntohs(dh->tid), ntohs(dh->flags));
				Information.AddString(str);
				str.Format("Query: %d Answer RRs: %d, Authority: %x", ntohs(dh->ques), ntohs(dh->ans), ntohs(dh->auth));
				Information.AddString(str);
				u_char *query = &(dh->dns_data);//��λ����ѯ����ͷ��
				u_char domainname[100] = { 0 };
				u_int i = 0;
				query++;//�ѵ�ȥ��
				while (*query)
				{
					if (*query < 0x10)//48�Ժ�������ֺ�Ӣ����ĸ
					{
						domainname[i] = '.';
					}
					else
					{
						domainname[i] = *query;
					}
					query++;
					i++;
				}
				str.Format("QueryDomain = %s", domainname);
				Information.AddString(str);

				query += 2; // '\0'
				u_short* type = (u_short*)query;
				switch (*type) { //query type
				case 0x0001:
					Information.AddString("Type: A");
					break;
				case 0x0002:
					Information.AddString("Type: NS");
					break;
				case 0x0005:
					Information.AddString("Type: CNAME");
					break;
				case 0x000c:
					Information.AddString("Type: PTR");
					break;
				case 0x001c:
					Information.AddString("Type: AAAA");
					break;
				}
				type++;
				if (*type == 0x0001) {
					Information.AddString("Class: IN");
				}
			}
			else if (sport == PROTOCOL_OICQ || dport == PROTOCOL_OICQ) {
				str = OICQ_analysis(uh, pkt_data + ip_len);
				Information.AddString(str);
			}
			else if (sport == PROTOCOL_SSDP || dport == PROTOCOL_SSDP) {
				str = SSDP_analysis(uh, pkt_data + ip_len);
				Information.AddString(str);
			}
			break;
		}

		default:
			printf("IPv4 Transport layer protocol not supportive yet.\n");
			break;
		}
		break;
	}

	case PROTOCOL_ARP: {
		arp_header *ah = (arp_header *)(pkt_data +
			14); //��̫��ͷ������
		str.Format("Network layer: ARP\n");
		Information.AddString(str);
		str.Format("Sender Mac address: %x.%x.%x.%x.%x.%x",
			*ah->arp_eth_src,
			*(ah->arp_eth_src + 1),
			*(ah->arp_eth_src + 2),
			*(ah->arp_eth_src + 3),
			*(ah->arp_eth_src + 4),
			*(ah->arp_eth_src + 5)
		);
		Information.AddString(str);
		str.Format("Sender IP address: %d.%d.%d.%d",
			ah->saddr.byte1,
			ah->saddr.byte2,
			ah->saddr.byte3,
			ah->saddr.byte4
		);
		Information.AddString(str);
		str.Format("Target Mac address: %x.%x.%x.%x.%x.%x",
			*ah->arp_eth_dst,
			*(ah->arp_eth_dst + 1),
			*(ah->arp_eth_dst + 2),
			*(ah->arp_eth_dst + 3),
			*(ah->arp_eth_dst + 4),
			*(ah->arp_eth_dst + 5)
		);
		Information.AddString(str);
		str.Format("Target IP address: %d.%d.%d.%d",
			ah->daddr.byte1,
			ah->daddr.byte2,
			ah->daddr.byte3,
			ah->daddr.byte4
		);
		Information.AddString(str);
		break;
	}

	case PROTOCOL_IPv6: {
		str.Format("Network layer: IPv6\n");
		Information.AddString(str);
		/* ���IP���ݰ�ͷ����λ�� */
		ipv6_header *ih6 = (ipv6_header *)(pkt_data +
			14); //��̫��ͷ������
		u_char protocol = ih6->nh;
		switch (protocol) {
		case PROTOCOL_TCP: {
			str = TCP_analysis(ih6, pkt_data + 14);
			Information.AddString(str);
			break;
		}
		case PROTOCOL_ICMPv6: {
			icmpv6_header* ich = (icmpv6_header*)((u_char*)ih6 + 40);//ipv6�ײ�����
			str.Format("Application layer: ICMPv6 Type: %d Code: %d", ich->type, ich->code);
			Information.AddString(str);
			break;
		}
		case PROTOCOL_UDP: {
			str = UDP_analysis(ih6, pkt_data + 14);
			Information.AddString(str);
			break;
		}
		default: {
			str.Format("IPv6 Transport layer protocol not supportive yet.\n");
			break;
		}
		}
		break;
	}

	default: {
		str = ("Network layer protocol supportive yet.\n");
		Information.AddString(str);
	}

	}
	Information.UpdateData(FALSE);
}

LRESULT PacketDlg::OnUpdatePacket(WPARAM wParam, LPARAM lParam)
{
	CString str;
	str = *((CString*)wParam);
	packetList.AddString(str);
	packetList.UpdateData(false);
	return LRESULT();
}


void PacketDlg::OnBnClickedStop()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if (p_myThread == NULL)//�����߳������ɹ�
	{
		AfxMessageBox(_T("�̲߳�����"));
	}
	else
	{
		flag_myThread = TRUE;//��ֹ
		dumpfile = NULL;
		SetDlgItemInt(IDC_NUMBER, 0, false);
		packetList.ResetContent();
		Information.ResetContent();
	}
}


void PacketDlg::OnBnClickedReturn()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	//GetParent()->ShowWindow(SW_SHOW);
	
}
