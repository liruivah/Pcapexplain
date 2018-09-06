

/*
	pacp file explainer 
	head file
	struct define 

	debug:
*/

#ifndef pcapexplain_pcap_h
#define pcapexplain_pcap_h

/*
Pcap file header 24B：
Magic：4B：0x1A 2B 3C 4D:start
Major：2B，0x02 00:version
Minor：2B，0x04 00
ThisZone：4B
SigFigs：4B
SnapLen：4B
LinkType：4B
type：
　0            BSD loopback devices, except for later OpenBSD
 1            Ethernet, and Linux loopback devices
 6            802.5 Token Ring
 7            ARCnet
 8            SLIP
 9            PPP
 */
#include<string>
typedef unsigned int u_int32;
typedef unsigned short u_short;
typedef unsigned char BYTE;
typedef int int32;
typedef unsigned long DWORD;
#pragma pack(1)
typedef struct pcap_file_header{
	u_int32 magic;
	u_short major;
	u_short minor;
	u_int32 ThisZone;
	u_int32 SigFigs;
	u_int32 SnapLen;
	u_int32 LinkType;

} pcap_file_header;


typedef struct timestamp{
	u_int32 timestamp_s;
	u_int32 timestamp_ms;

}timestamp;

typedef struct pcap_header{
	timestamp ts;
	u_int32 capture_len;
	u_int32 len;

} pcapheader;

typedef struct FrameHeader_t{
	BYTE DesMac[6];
	BYTE SrcMac[6];
	u_short FrameType;
}FrameHeader_t;

// Ipv4 header, 
typedef struct IPFrame_t{
	BYTE Ver_Hlen;
	BYTE TOS;
	u_short TotalLen;
	u_short ID;
	u_short Flag_Segment;
	BYTE TLL;
	BYTE Protocol;
	u_short Checksum;
	DWORD SrcIP;
	DWORD DstIP;
} IPFrame_t;

typedef struct Data_t{
	FrameHeader_t FrameHeader;
	IPFrame_t IPHeader;
}Data_t;


typedef struct Tcp_header{
	u_short SrcPort;
	u_short DstPort;
	u_int32 SeqNo;
	u_int32 AckNo;
	BYTE HeaderLen;
	BYTE Flags;
	u_short Window;
	u_short Checksum;
	u_short UrgentPointer;
}Tcp_header;

typedef struct Udp_header{
	u_short SrcPort;
	u_short DstPort;
	u_short length;
	u_short Checksum;

	
}Udp_header;

#pragma pack()
void prinfPcapFileHeader(pcap_file_header *pfh);
void printfPcapHeader(pcap_header *ph);
int printPcap(void * data, size_t size, std::string outfile);

#define target_file "outfile1";


#endif 
