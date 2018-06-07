#ifndef EXTRACT_PACKET_H
#define EXTRACT_PACKET_H

#include <pcap/pcap.h>

/*
stat info of a savefile

Members:
  unsigned long long pkt_num: number of packets in the pcap file;
*/
typedef struct pcap_stat_offline {
  unsigned long long pkt_num
};

/*
process a pcap file to extract all the ip packets

Args:
  const char* fname: pcap file name;
  char* errbuf: buffer to store error message
*/
struct pcap_stat_offline extract_ip_pkt(const char* fname, char* errbuf);

#endif