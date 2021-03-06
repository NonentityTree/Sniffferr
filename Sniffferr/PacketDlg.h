#pragma once
#include "stdafx.h"
#include <pcap.h>

int start(pcap_dumper_t *dumpfile, pcap_t *adhandle, HWND hWnd);
int capture(pcap_dumper_t *dumpfile, pcap_t *adhandle, struct pcap_pkthdr *header, const u_char *pkt_data);
int parseNshow(pcap_t *adhandle, struct pcap_pkthdr *header, const u_char *pkt_data, HWND hWnd);


// PacketDlg 对话框
class PacketDlg : public CDialogEx
{
	DECLARE_DYNAMIC(PacketDlg)

public:
	PacketDlg(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~PacketDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PACKET_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	
	pcap_if_t *alldevs;   //所有网卡设备列表
	pcap_if_t *d;         //当前选中网卡
	pcap_t *adhandle;

	
	pcap_dumper_t *dumpfile;
	pcap_t *fp;
	char *filename;

	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	CWinThread* p_myThread;//创建线程指针
	BOOL flag_myThread = FALSE;//是否终止

	static UINT MyThreadFunction(LPVOID pParam);//定义线程入口函数

	CListBox packetList;

	// 设置过滤器
	CComboBox filter;
	afx_msg void OnCbnSelchangeFilterCombo();
	afx_msg void OnBnClickedStart();
	afx_msg void OnBnClickedPause();
	afx_msg void OnBnClickedStop();

	afx_msg void OnLbnSelchangePacketList();

	afx_msg LRESULT OnUpdatePacket(WPARAM wParam, LPARAM lParam);
	
	CListBox Information;
	afx_msg void OnBnClickedReturn();
};

