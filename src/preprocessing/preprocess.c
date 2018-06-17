#include "preprocess.h"
#include <arpa/inet.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Internel functions */

/*
extract udp packet and add padding after udp header

Args:
  const u_char* pdt_data: packet actual bytes;
  uint8_t* dpkt: deep packet buffer, all zeros(guarented by calling function);
  packet_t pkt: struct restore the target data
*/
void extract_tcp_pkt(const struct pcap_pkthdr* hdr, const uint8_t* pkt_data,
                     packet_t* pkt) {
  int min = fmin(hdr->caplen, DEEP_PACKET_LEN);
#ifdef NO_EMPTY_PAYLOAD
  uint8_t tcp_header_len =
      4 * (*(pkt_data + ETHERNET_2_HEAD_LEN + IPV4_HEAD_LEN + 12) >> 4);
  uint8_t all_header_len = ETHERNET_2_HEAD_LEN + IPV4_HEAD_LEN + tcp_header_len;
  if ((hdr->caplen - all_header_len) == 0) {
    return 0;
  }
#endif
  memcpy((*pkt).raw, pkt_data + ETHERNET_2_HEAD_LEN, min);
}

/*
extract udp packet and add padding after udp header

Args:
  const struct pcap_pkthdr* pkthdr: packet info;
  const u_char* pdt_data: packet actual bytes;
  packet_t pkt: struct restore the target data
*/
void extract_udp_pkt(const struct pcap_pkthdr* hdr, const uint8_t* pkt_data,
                     packet_t* pkt) {
  int min = fmin(hdr->caplen, DEEP_PACKET_LEN);
  uint8_t pad_buf[12] = {0};
  // copy ipv4 header and upd header
  memcpy((*pkt).raw, pkt_data + ETHERNET_2_HEAD_LEN,
         IPV4_HEAD_LEN + UDP_HEAD_LEN);
  // add padding zeros
  memcpy((*pkt).raw + IPV4_HEAD_LEN + UDP_HEAD_LEN, pad_buf, 12);
  // copy udp payload
  memcpy((*pkt).raw + IPV4_HEAD_LEN + UDP_HEAD_LEN + 12,
         pkt_data + ETHERNET_2_HEAD_LEN + IPV4_HEAD_LEN + UDP_HEAD_LEN,
         min - (IPV4_HEAD_LEN + UDP_HEAD_LEN + 12));
}

/*
extract ip packet from a whole packet

Args:
  const struct pcap_pkthdr* pkthdr: packet info;
  const u_char* pdt_data: packet actual bytes;
  pcap_stat_t* stat_info: pcap file stat info;
  int protocol: used to determine extract tcp or udp
*/
int extract_ipv4_pkt(const struct pcap_pkthdr* hdr, const uint8_t* pkt_data,
                     pcap_stat_t* stat_info, packet_t* pkt, int protocol) {
  uint8_t tl_protocol = pkt_data[ETHERNET_2_HEAD_LEN + 9];

  if (protocol == TCP_PROTOCOL && tl_protocol == TCP_PROTOCOL) {
    (*stat_info).tcp_pkt_num++;
    extract_tcp_pkt(hdr, pkt_data, pkt);
  } else if (protocol == UDP_PROTOCOL && tl_protocol == UDP_PROTOCOL) {
    (*stat_info).udp_pkt_num++;
    extract_udp_pkt(hdr, pkt_data, pkt);
  }
  return 0;
}

/*
extract packet from a Ethernet II protocol packet

Args:
  const struct pcap_pkthdr* pkthdr: packet info;
  const u_char* pdt_data: packet actual bytes;
  pcap_stat_t* stat_info: pcap file stat info
*/
int extract_eth_pkt(const struct pcap_pkthdr* hdr, const uint8_t* pkt_data,
                    pcap_stat_t* stat_info, packet_t* pkt, int protocol) {
  uint16_t nl_protocol =
      htons(*(uint16_t*)(pkt_data + 12)); /* network layer protocol */
  int res;
  if (nl_protocol == IPV4_PROTOCOL) {
    (*stat_info).ip_pkt_num++;
    res = extract_ipv4_pkt(hdr, pkt_data, stat_info, pkt, protocol);
    return res;
  }
  return 0;
}

/*
write a processed ip packet to a csv file

Args:
  const char* fname:  csv file name;
  const uint8_t* dpkt: packet to be write;
  int id: packet id in pcap file
*/
int write_pkt_2_csv(const char* fname, const packet_t pkt) {
  FILE* fp = fopen(fname, "a");
  if (!fp) {
    perror("File opening failed");
    return EXIT_FAILURE;
  }

  char record[CSV_ROW_BUF_LEN] = {0};
  char buf[10];

  sprintf(buf, "%d,", pkt.id);
  strcat(record, buf);

  for (int i = 0; i < DEEP_PACKET_LEN; i++) {
    if (i == DEEP_PACKET_LEN - 1) {
      sprintf(buf, "%d", pkt.raw[i]);
    } else {
      sprintf(buf, "%d,", pkt.raw[i]);
    }
    strcat(record, buf);
  }
  strcat(record, "\n");

  fwrite(record, sizeof(char), strlen(record), fp);
  fclose(fp);
  return 0;
}

/* Public functions */

void print_stat_info(pcap_stat_t stat_info, int protocol) {
  printf("\nThere are %u packets in pcap file.", stat_info.pkt_num);
  printf("\nThere are %u ip packets in pcap file.", stat_info.ip_pkt_num);
  if (protocol == TCP_PROTOCOL) {
    printf("\nThere are %u tcp packets in pcap file.\n", stat_info.tcp_pkt_num);
  } else if (protocol == UDP_PROTOCOL) {
    printf("\nThere are %u udp packets in pcap file.", stat_info.udp_pkt_num);
  }
}

/*

*/
pcap_stat_t extract_pkt(const char* pcap_fname, const char* csv_fname,
                        int protocol, char* errbuf) {
  pcap_stat_t stat_info = {0};
  // check whether pcap file exists
  FILE* fp = fopen(pcap_fname, "r");
  if (!fp) {
    strcpy(errbuf, "pcap file not exists!");
    return stat_info;
  }
  fclose(fp);

  fp = fopen(csv_fname, "r");

  pcap_t* descr = pcap_open_offline(pcap_fname, errbuf);
  struct pcap_pkthdr* hdr;
  const uint8_t* pkt_data;
  packet_t packet = {0, {0}};
  int res;

  printf("Start processing pcap file: %s.\n", pcap_fname);

  while ((res = pcap_next_ex(descr, &hdr, &pkt_data)) == 1) {
    stat_info.pkt_num++;
    int link_type = pcap_datalink(descr);
    if (link_type == LINKTYPE_ETHERNET) {
      res = extract_eth_pkt(hdr, pkt_data, &stat_info, &packet, protocol);
    }
    if (link_type == LINKTYPE_RAW) {
      res = extract_ipv4_pkt(hdr, pkt_data, &stat_info, &packet, protocol);
    }
    if (res == 0) {
      write_pkt_2_csv(csv_fname, packet);
    }
  }
  print_stat_info(stat_info, protocol);
  return stat_info;
}
