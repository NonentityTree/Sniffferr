// PacketDlg.cpp: 实现文件
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

// PacketDlg 对话框

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
END_MESSAGE_MAP()


// PacketDlg 消息处理程序




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

	/* 开始捕捉 */
	pcap_loop(adhandle, 1, packet_handler, (unsigned char *)dumpfile);
	//pcap_next_ex(adhandle, &header, &pkt_data);
	//pcap_dump((unsigned char *)dumpfile, header, pkt_data);
	return 0;
}



UINT PacketDlg::MyThreadFunction(LPVOID pParam)
{
	//线程入口函数，具体实现
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

	dlg->p_myThread = NULL;//线程结束注销或线程不存在
	return 0;
}

void PacketDlg::OnCbnSelchangeFilterCombo()
{
	// TODO: 在此添加控件通知处理程序代码

}




void PacketDlg::OnBnClickedStart()
{
	// TODO: 在此添加控件通知处理程序代码
	if (dumpfile == NULL) {
		filename = "packet.cap";          //文件名
		dumpfile = pcap_dump_open(adhandle, filename);
	}
	CString str;   //过滤规则
	struct bpf_program fcode;            //BPF过滤机制
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
	if (p_myThread == NULL) //若无线程启动成功
	{    //创建并启动线程
		packetList.ResetContent();
		p_myThread = AfxBeginThread(MyThreadFunction, (LPVOID)this);//this赋给线程入口函数的参数pParam
		flag_myThread = FALSE;
	}
	else
	{
		p_myThread->ResumeThread();//继续
	}
}


void PacketDlg::OnBnClickedPause()
{
	// TODO: 在此添加控件通知处理程序代码
	/*mutex.lock();
	flag = false;
	mutex.unlock();*/
	if (p_myThread == NULL)//若无线程启动成功
	{
		AfxMessageBox(_T("线程不存在"));
	}
	else
	{
		p_myThread->SuspendThread();//暂停、挂起
	}
}

int parseNshow(pcap_t *adhandle, struct pcap_pkthdr *header, const u_char *pkt_data, HWND hWnd)
{
	time_t local_tv_sec;
	struct tm ltime;
	char timestr[16];
	CString str;
	/* 获取数据包 */
	/*pcap_t* fp = load_data();
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {*/

	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	ether_header * eheader = (ether_header*)(pkt_data);
	switch (ntohs(eheader->ether_type)) {
	case PROTOCOL_IPv4: {
		ip_header *ih = (ip_header *)(pkt_data +
			14); //以太网头部长度
		//IP源->目的地址
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
			14); //以太网头部长度
		//IP源->目的地址
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
	default:
		str += ("   Network layer protocol not supportive yet");
	}
	SendMessage(hWnd, UPDATEPACKET, (WPARAM)(&str), 0);
	return 0;
}






void PacketDlg::OnLbnSelchangePacketList()
{
	// TODO: 在此添加控件通知处理程序代码
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

	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* 打印数据包的时间戳和长度 */
	str.Format("Time: %s.%.6d", timestr, header->ts.tv_usec);
	Information.AddString(str);
	str.Format("Length: %d", header->len);
	Information.AddString(str);

	/* 获得IP数据包头部的位置 */
	ip_header *ih = (ip_header *)(pkt_data +
		14); //以太网头部长度
	ether_header * eheader = (ether_header*)(pkt_data);
	//以太网源->目的地址
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
		/* 获得IP数据包头部的位置 */
		ip_header *ih = (ip_header *)(pkt_data +
			14); //以太网头部长度
		u_int ip_len;
		u_short sport, dport;
		/* 获得UDP首部的位置 */
		ip_len = (ih->ver_ihl & 0xf) * 4;//ip首部长度

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
					//GET请求
					if (!find_http && i + 3 < t_len && (strncmp(ip_pkt_data + i, "GET", strlen("GET")) == 0))
						find_http = true;
					//POST请求
					if (!find_http && i + 4 < t_len && (strncmp(ip_pkt_data + i, "POST", strlen("POST")) == 0))
						find_http = true;
					//响应
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
				str = DHCP_analysis(uh, pkt_data + ip_len);
				Information.AddString(str);
			}
			else if (sport == PROTOCOL_DNS || dport == PROTOCOL_DNS) {
				/*str = DNS_analysis(uh, pkt_data + ip_len);
				Information.AddString(str);*/
				dns_header* dh = (dns_header*)((u_char*)uh + 8);//udp首部8字节
				Information.AddString("Application layer: DNS");
				str.Format("TID: %x, Flags: %x", ntohs(dh->tid), ntohs(dh->flags));
				Information.AddString(str);
				str.Format("Query: %d Answer RRs: %d, Authority: %x", ntohs(dh->ques), ntohs(dh->ans), ntohs(dh->auth));
				Information.AddString(str);
				u_char *query = &(dh->dns_data);//定位到查询部分头部
				u_char domainname[100] = { 0 };
				u_int i = 0;
				query++;//把点去了
				while (*query)
				{
					if (*query < 0x10)//48以后出现数字和英文字母
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
		str = ARP_analysis(header, pkt_data);
		break;
	}

	case PROTOCOL_IPv6: {
		str.Format("Network layer: IPv6\n");
		Information.AddString(str);
		/* 获得IP数据包头部的位置 */
		ipv6_header *ih6 = (ipv6_header *)(pkt_data +
			14); //以太网头部长度
		u_char protocol = ih6->nh;
		switch (protocol) {
		case PROTOCOL_TCP: {
			str = TCP_analysis(ih6, pkt_data + 14);
			Information.AddString(str);
			break;
		}
		case PROTOCOL_ICMPv6: {
			str = ICMPv6_analysis(ih6, pkt_data + 14);
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
	// TODO: 在此添加控件通知处理程序代码
	if (p_myThread == NULL)//若无线程启动成功
	{
		AfxMessageBox(_T("线程不存在"));
	}
	else
	{
		flag_myThread = TRUE;//终止
		dumpfile = NULL;
	}
}
