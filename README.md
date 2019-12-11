# Sniffferr
（一）Winpcap相关记录
1. int pcap_findalldevs_ex(char *source, struct pcap_rmtauth *auth, pcap_if_t ** alldevs, char * errbuf)  
构造一个可打开的网络设备的列表
参数：source location（寻找本地/远程适配器），auth（本地为NULL），alldevs（指向适配器列表第一个元素），errbuf（错误信息）
返回值：0正常，-1错误

2. void pcap_freealldevs(pcap_if_t * alldevsp	)  
释放设备列表

3. pcap_t* pcap_open	(const char *source, int 	snaplen, int flags, int read_timeout, struct pcap_rmtauth * auth, char * 	errbuf)
打开一个适配器
参数：source（目标适配器），snaplen（要捕捉数据包的长度，65535保证能捕获到不同数据链路层上的每个数据包的全部内容），flags（设置模式PCAP_OPENFLAG_PROMISCUOUS为混杂模式），read_timeout（读取超时时间），auth，errbuf
返回值：一个已打开捕捉事例的描述符pcap_t

4. int pcap_datalink	(pcap_t * p) 	
返回一个适配器的链路层信息
主要返回值：DLT_EN10MB（Ethernet），DLT_IEEE802（IEEE 802.5）

5. int pcap_compile	(pcap_t * p, struct bpf_program * 	fp, char * str,  int 	optimize, bpf_u_int32 netmask)	
编译数据包过滤器
参数：p，bpf_program（过滤器程序指针），str（设置的过滤规则），optimize（是否进行优化），netmask（确认捕获网络包所在的网络的IPv4掩码，仅在过滤器程序检查广播地址时用到）

6. int pcap_setfilter	(pcap_t * p, struct bpf_program * 	fp)	
在捕获过程中绑定一个过滤器

7. int pcap_dispatch (pcap_t * p, int cnt, pcap_handler callback, u_char * 	user	)	
捕获一个数据包
参数：p，cnt（捕捉数据包数量），callback（回调函数，每捕获一个数据包都会调用该函数），user
返回值：0未捕获到数据包（超时/不符合过滤规则/无可捕获的包），-1错误，-2循环结束，>0返回捕获数据包数量

8. int pcap_loop(pcap_t * p, int cnt, pcap_handler callback, u_char * 	user	)	
捕获一个数据包，不会因为超时而返回，会在一小段时间内阻塞网络的利用

9. int pcap_next_ex	(pcap_t * p, struct pcap_pkthdr ** pkt_header, const u_char ** pkt_data)	
无回调函数捕获一个数据包
参数：p，pkt_header（数据包的时间戳+长度）, pkt_data

10. pcap_dumper_t* pcap_dump_open(pcap_t * p, const char * fname)
打开堆文件

11. void pcap_dump(u_char * user, const struct pcap_pkthdr * 	h, const u_char * sp)	
保存数据包到堆文件 pcap_dump(dumpfile, header, pkt_data);
