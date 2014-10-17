#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct IpHeader//IP头
{
	u_char ver_headLength;
	u_char tos;
	u_short totallen;
	u_short identification;
	u_short flags_offset;
	u_char ttl;
	u_char proto;
	u_short headChecksum;
	struct in_addr sourAddr;
	struct in_addr destAddr;
}IpHeader;

extern char * Proto[];//一个协议编号的指针数组

void showdata(const struct pcap_pkthdr *pkthdr,const u_char *packet)//输出原始数据的函数
{
	int i;
	printf("The original data:\n");
	for(i=0;i<pkthdr->len;i++)
	{
		printf("%02x",packet[i]);
		if((i+1)%20==0)
                {
                        printf("\n");
                }
        }
}

void getPacket(u_char *arg,const struct pcap_pkthdr *pkthdr,const u_char *packet)//回调函数
{
	int *id=(int *)arg;
	printf("Id: %d\n",++(*id));
	printf("Packet length: %d\n",pkthdr->len);
	printf("Recieved time: %s",ctime((const time_t *)&pkthdr->ts.tv_sec));
	
	const u_char *data=packet;
	u_short eth_proto=ntohs(*((short *)(data+12)));//以太头中的协议号
	int i;
	if(eth_proto==0x0800)//IPv4
	{
		short proto=(int)(*(data+23));//IP头中的协议号
		IpHeader *ipheader=(IpHeader *)(data+14);
		printf("The source IP address is %s\n",inet_ntoa(ipheader->sourAddr));//source IP address
		printf("The destination IP address is %s\n",inet_ntoa(ipheader->destAddr));//destination IP address
		printf("The protocal is %s\n",Proto[proto]);
		showdata(pkthdr,packet);
	}
	else if(eth_proto==0x86dd)//IPv6
	{
		printf("The protocal is IPv6\n");
		showdata(pkthdr,packet);
	}
	else if(eth_proto==0x806)//ARP
	{
		printf("The protocal is ARP\n");
		showdata(pkthdr,packet);
	}
	printf("\n\n");
}

int main()
{
	char errBuf[PCAP_ERRBUF_SIZE],*devStr;

	devStr=pcap_lookupdev(errBuf);
	
	if(devStr)
		printf("sucess!device %s is founded!\n",devStr);
	else
	{
		printf("Error!\n");
		exit(1);
	}
	
	pcap_t *device = pcap_open_live(devStr,65535,1,0,errBuf);
	
	if(!device)
	{
		printf("Open Device Error!\n");
		exit(1);
	}
	
	int id=0;

	pcap_loop(device,-1,getPacket,(u_char *)&id);
	
	pcap_close(device);
	
	return 0;
}
