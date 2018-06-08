#ifndef EXTRACT_PACKET_H
#define EXTRACT_PACKET_H

#include <pcap/pcap.h>

#define ETHERNET_2_HEAD_LEN 14
#define IPV4_HEAD_LEN 20
#define TCP_HEAD_LEN 20
#define UDP_HEAD_LEN 8

#define DEEP_PACKET_LEN 1500

#define IPV4_PROTOCOL 0x0800
#define TCP_PROTOCOL 0x06
#define UDP_PROTOCOL 0x11

/*
stat info of a savefile

Members:
  unsigned long long pkt_num: number of packets in the pcap file;
*/
typedef struct pcap_stat_offline {
  unsigned long long pkt_num;
  unsigned long long ip_pkt_num;
  unsigned long long tcp_pkt_num;
  unsigned long long udp_pkt_num;
} pcap_stat_offline_t;

/*
process a pcap file to extract all the ip packets

Args:
  const char* fname: pcap file name;
  char* errbuf: buffer to store error message
*/
struct pcap_stat_offline extract_nl_pkt(const char* fname, char* errbuf);

#endif