
// SniffferrDlg.h: ͷ�ļ�
//
#include "stdafx.h"
#pragma once
#include <pcap.h>

// CSniffferrDlg �Ի���
class CSniffferrDlg : public CDialogEx
{
	// ����
public:
	CSniffferrDlg(CWnd* pParent = nullptr);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFFERR_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;
	pcap_if_t *alldevs;  //���������б�
	pcap_if_t *d;  //ѡ������
	pcap_t *adhandle;


	// ���ɵ���Ϣӳ�亯��
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

