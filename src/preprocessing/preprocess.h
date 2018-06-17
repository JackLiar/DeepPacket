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

#ifdef ONLY_TRANSPORT_LAYER
#define DEEP_PACKET_LEN 1000
#else
#define DEEP_PACKET_LEN 1500
#endif

// 8(id) + 1500*3(byte value) + 1500(comma) + 1("\n" in the end)
#define CSV_ROW_BUF_LEN 6009

#define IPV4_PROTOCOL 0x0800

#define TCP_PROTOCOL 0x06
#define UDP_PROTOCOL 0x11

#define LINKTYPE_ETHERNET 0x0001
#define LINKTYPE_RAW 0x0065

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
} pcap_stat_t;

/*
target packet data

there's gonna be 2 modes:
  1. whole network layer packet(ip packet)
  2. just transport layer packet payload (tcp/udp)

Since the src ip and dst ip are limited to several values in the example pcap
files, so ip address and ip header may be useless in machine learning.
*/
typedef struct packet {
  int id;                       /* frame id in the pcap file */
  uint8_t raw[DEEP_PACKET_LEN]; /* ip packet raw data */
} packet_t;

/*
process a pcap file to extract all the packets

Args:
  const char* pcap_fname: pcap file name;
  const char* csv_fname: pcap file name;
  int protocol: which transport layer protocol(tcp/udp) to be extracted;
  char* errbuf: buffer to store error message
*/
pcap_stat_t extract_pkt(const char* pcap_fname, const char* csv_fname,
                        int protocol, char* errbuf);

/*
print stat information of a pcap file

Args:
  pcap_statt stat_info: stat information of a pcap file
*/
void print_stat_info(pcap_stat_t stat_info, int protocol);

#endif