
// SniffferrDlg.cpp: ʵ���ļ�
//

#include "stdafx.h"
#include "Sniffferr.h"
#include "SniffferrDlg.h"
#include "PacketDlg.h"
#include "afxdialogex.h"
#include "sniffer.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CSniffferrDlg �Ի���



CSniffferrDlg::CSniffferrDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SNIFFFERR_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSniffferrDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_INTERFACE_LIST, m_interfaceList);
}

BEGIN_MESSAGE_MAP(CSniffferrDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CSniffferrDlg::OnBnClickedOk)
	ON_LBN_SELCHANGE(IDC_INTERFACE_LIST, &CSniffferrDlg::OnLbnSelchangeInterfaceList)
END_MESSAGE_MAP()


// CSniffferrDlg ��Ϣ�������

BOOL CSniffferrDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	m_interfaceList.SetHorizontalExtent(2000);

	alldevs = getDevList();
	pcap_if_t *d;
	for (d = alldevs; d; d = d->next)
	{
		CString dev = d->name;
		if (d->description)
			dev.Append(d->description);
		m_interfaceList.AddString(dev);

	}

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CSniffferrDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CSniffferrDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CSniffferrDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}




void CSniffferrDlg::OnBnClickedOk()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	this->ShowWindow(SW_HIDE);
	CDialogEx::OnOK();
	PacketDlg pktDlg;           // ����Ի�����CTipDlg��ʵ��   
	pktDlg.alldevs = alldevs;
	pktDlg.d = d;
	pktDlg.adhandle = adhandle;
	pktDlg.DoModal();// �����Ի��� 

	this->ShowWindow(SW_SHOW);

}


void CSniffferrDlg::OnLbnSelchangeInterfaceList()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	int nCurSel;
	nCurSel = m_interfaceList.GetCurSel();    // ��ȡ��ǰѡ���б���
	d = chooseDev(alldevs, nCurSel);
	adhandle = openDev(d, alldevs);
}
