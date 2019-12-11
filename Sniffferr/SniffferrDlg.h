
// SniffferrDlg.h: 头文件
//
#include "stdafx.h"
#pragma once
#include <pcap.h>

// CSniffferrDlg 对话框
class CSniffferrDlg : public CDialogEx
{
	// 构造
public:
	CSniffferrDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFFERR_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	pcap_if_t *alldevs;  //所有网卡列表
	pcap_if_t *d;  //选中网卡
	pcap_t *adhandle;


	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnLbnSelchangeInterfaceList();
	CListBox m_interfaceList;
};

