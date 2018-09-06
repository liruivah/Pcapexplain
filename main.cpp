#include<iostream>
#include<fstream>
#include<string.h>
#include<io.h>
#include<vector>
#include <winsock2.h>
#include "pcap.h"
using namespace std;


#define file_path "data.pcap"
#define ERROR_FILE_OPEN_FAILED -1  
#define ERROR_MEM_ALLOC_FAILED -2  
#define ERROR_PCAP_PARSE_FAILED -3 
#define MAX_ETH_FRAME 3028  
//get extension
inline string getExtension(const string &fileName)
{
	string extension;
	if (fileName.rfind('.') != string::npos) {
		extension = fileName.substr(fileName.rfind('.') + 1);
	}
	return extension;
}

//match extension
bool matchExtension(const string &fileName, const string &extension)
{
	char *str = (char *)malloc(extension.length() + 1);
	char *ext = (char *)malloc(getExtension(fileName).length() + 1);
	strcpy(str, extension.c_str());
	strcpy(ext, getExtension(fileName).c_str());

	bool isMatch = false;
	char *p = strtok(str, "|");

	while (p && !isMatch) {
		if (strcmp(ext, p) == 0) {
			isMatch = true;
		}
		p = strtok(NULL, "|");
	}
	free(str);
	free(ext);

	return isMatch;
}
// read all pcap file 
void getFiles(string path, vector<string>& files)
{
	intptr_t hFile = 0;
	struct _finddata_t fileinfo;
	string p;
	if ((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) != -1)
	{
		do
		{
			if ((fileinfo.attrib &  _A_SUBDIR))
			{
				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0)
					getFiles(p.assign(path).append("\\").append(fileinfo.name), files);
			}
			else
			{
				p.assign(path).append("\\").append(fileinfo.name);
				if (matchExtension(fileinfo.name, "pcap"))
					files.push_back(p);
			}
		} while (_findnext(hFile, &fileinfo) == 0);
		_findclose(hFile);
	}
}
int main(){
	//cout << "u_int:"<<sizeof(unsigned int)<<"int:" << sizeof(int)<<"u_short:" << sizeof(unsigned short) << endl;
	pcap_file_header pfh;
	pcapheader ph;
	Data_t dh;
	int count = 0; 
	void * buff = NULL;
	int readSize = 0;
	int ret = 0;
	// pacp file path
	string filePath = "pcap file paths...";
	vector<string> files;
	
	////get all pcap files
	getFiles(filePath, files);
	int size = files.size();
	for(int i=0;i<size;i++){
		ifstream binary_file;
		binary_file.open(files[i], ios::binary | ios::in);

		if (!binary_file) {
			cout << "read file " << files[i] << " error" << endl;
			ret = ERROR_FILE_OPEN_FAILED;
			break;
		}

		binary_file.read(reinterpret_cast<char *>(&pfh), sizeof(pcap_file_header));
		//prinfPcapFileHeader(&pfh);
		buff = (void*)malloc(MAX_ETH_FRAME);

		for (count = 1;; count++) {
			if (count > 3000) {
				binary_file.close();
				binary_file.clear();
				break;
			}

	        memset(buff, 0, MAX_ETH_FRAME);


			if (!binary_file.read(reinterpret_cast<char *>(&ph), sizeof(pcap_header))) {
				break;
			}
			if (buff == NULL) {
				cout << "malloc memory failed." << endl;
				ret = ERROR_MEM_ALLOC_FAILED;
				break;
			}
			//header
			binary_file.read(reinterpret_cast<char *>(&dh), sizeof(Data_t));
			//headersize
			int n = 0;
			int packettail = 0;
			//udp or tcp
			BYTE protocol = 0x00;
			packettail = ph.capture_len- sizeof(Data_t);
			//remove ipv4 or ipv6 header 
			if ((dh.IPHeader.Ver_Hlen>>4) == 0x04) {// remove ipv4 option
				n = 4*(dh.IPHeader.Ver_Hlen&0x0f) - sizeof(IPFrame_t);
				readSize = ntohs(dh.IPHeader.TotalLen) - sizeof(IPFrame_t)-n;
				protocol = dh.IPHeader.Protocol;
				if (n < 0)
					n =0;
			}
			else if ((dh.IPHeader.Ver_Hlen>>4) == 0x06) {//length of ipv6 header is 40
				n = 40 * sizeof(BYTE) - sizeof(IPFrame_t);
				readSize = ntohs(dh.IPHeader.ID);
				// Ipv6 structure is different from ipv4, the following data is the next protocol
				protocol = dh.IPHeader.Flag_Segment&0x0f;
			}
			packettail -= n;
			//remove
			binary_file.read(reinterpret_cast<char *>(buff), n);
			n = 0;
			if (protocol == 0x06) {
				Tcp_header th;
				binary_file.read(reinterpret_cast<char *>(&th), sizeof(Tcp_header));
				n = 4*(th.HeaderLen>>4)-sizeof(Tcp_header);// remove tcp option
				readSize -= 4*(th.HeaderLen >> 4);
				packettail -= 4*(th.HeaderLen >> 4);
			}
			if (protocol == 0x11) {
				n = sizeof(Udp_header);
				readSize -= n;
				packettail -= n;
			}
			binary_file.read(reinterpret_cast<char *>(buff), n);// remove tcp option or udp head
			memset(buff, 0, MAX_ETH_FRAME);
			if (readSize <= 0) {
				if (packettail > 0) {//remove tail (if have)
					binary_file.read(reinterpret_cast<char *>(buff), packettail);
				}
				continue;
			}
			binary_file.read(reinterpret_cast<char *>(buff), readSize);//read date segment
			string outfile = files[i]+"out1";
			ret = printPcap(buff, readSize,outfile);			//write
			if (ret < 0) {
				break;
			}
			printf("===count:%d,readSize:%d===\n", count, readSize);
			packettail -= readSize;
			if (packettail > 0) {//remove tail (if have)
				binary_file.read(reinterpret_cast<char *>(buff), packettail);
			}
			if (binary_file.eof() || readSize <= 0) {
				binary_file.close();
				binary_file.clear();
				break;
			}
		}
	}
	//free  
	if (buff) {
		free(buff);
		buff = NULL;
	}

	return ret;

}
