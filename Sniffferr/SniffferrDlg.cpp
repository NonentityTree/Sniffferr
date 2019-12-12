
// SniffferrDlg.cpp: 实现文件
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


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// CSniffferrDlg 对话框



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


// CSniffferrDlg 消息处理程序

BOOL CSniffferrDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
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

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSniffferrDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CSniffferrDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}




void CSniffferrDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnOK();
	PacketDlg dlg;   // 构造对话框类Dlg的实例   
	dlg.alldevs = alldevs;
	dlg.d = d;
	dlg.adhandle = adhandle;
	dlg.DoModal();// 弹出对话框 
	
	//this->ShowWindow(SW_HIDE);
	//this->ShowWindow(SW_SHOW);

}


void CSniffferrDlg::OnLbnSelchangeInterfaceList()
{
	// TODO: 在此添加控件通知处理程序代码
	int nCurSel;
	nCurSel = m_interfaceList.GetCurSel();    // 获取当前选中列表项
	d = chooseDev(alldevs, nCurSel);
	adhandle = openDev(d, alldevs);
}
