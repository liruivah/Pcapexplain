#include "pcap.h"
#include<stdio.h>
#include<fstream>
#include <winsock2.h>
#include<string>

#include<stdio.h>


void prinfPcapFileHeader(pcap_file_header *pfh){
	if (pfh==NULL){
		return;
	}
	printf("=====================\n"
		"magic:0x%0x\n"
		"version_major:%u\n"
		"version_minor:%u\n"
		"thiszone:%d\n"
		"sigfigs:%u\n"
		"snaplen:%u\n"
		"linktype:%u\n"
		"=====================\n",
		pfh->magic,
		pfh->major,
		pfh->minor,
		pfh->ThisZone,
		pfh->SigFigs,
		pfh->SnapLen,
		pfh->LinkType);
}

void printfPcapHeader(pcap_header *ph){
	if (ph == NULL) {
		return;
	}
	printf("=====================\n"
		"ts.timestamp_s:%u\n"
		"ts.timestamp_ms:%u\n"
		"capture_len:%u\n"
		"len:%d\n"
		"=====================\n",
		ph->ts.timestamp_s,
		ph->ts.timestamp_ms,
		ph->capture_len,
		ph->len);


}

int printPcap(void * data, size_t size,std::string file){
	unsigned  short iPos = 0;
	//int * p = (int *)data;  
	//unsigned short* p = (unsigned short *)data;  
	if (data == NULL) {
		return -1;
	}
	std::ofstream outfile;
	outfile.open(file, std::ios::app | std::ios::binary | std::ios::out);

//	printf("\n==data:0x%x,len:%lu=========", data, size);
	outfile.write(reinterpret_cast<char *>(&size),sizeof(size));
	/// 000000007d are writed with 7d00000000 
	outfile.write(reinterpret_cast<char *>(data), size);
	return 0;
}
