#pragma once
#ifndef EXTRACT_PACKET_H
#define EXTRACT_PACKET_H

#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>

#define ETHERNET_2_HEAD_LEN 14
#define IPV4_HEAD_LEN 20
#define TCP_HEAD_LEN 20
#define UDP_HEAD_LEN 8

#define DEEP_PACKET_LEN 1500
// 8(id) + 1500*3(byte value) + 1500(comma) + 1("\n" in the end)
#define CSV_ROW_BUF_LEN 6009

#define IPV4_PROTOCOL 0x0800

#define TCP_PROTOCOL 0x06
#define UDP_PROTOCOL 0x11

/*
stat info of a savefile

Members:
  unsigned long long pkt_num: number of packets in the pcap file;
*/
typedef struct pcap_stat_offline {
  uint32_t pkt_num;
  uint32_t ip_pkt_num;
  uint32_t tcp_pkt_num;
  uint32_t udp_pkt_num;
} pcap_stat_offline_t;

/*
ip (modifiled) packet struct
*/
typedef struct ip_packet {
  int id;                       /* frame id in the pcap file */
  uint8_t raw[DEEP_PACKET_LEN]; /* ip packet raw data */
} ip_pkt_t;

/*
process a pcap file to extract all the ip packets

Args:
  const char* fname: pcap file name;
  char* errbuf: buffer to store error message
*/
struct pcap_stat_offline extract_nl_pkt(const char* pcap_fname,
                                        const char* csv_fname, char* errbuf);

/*
print stat information of a pcap file

Args:
  pcap_stat_offline_t stat_info: stat information of a pcap file
*/
void print_stat_info(pcap_stat_offline_t stat_info);

#endif