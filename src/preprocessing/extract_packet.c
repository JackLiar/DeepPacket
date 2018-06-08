#include "extract_packet.h"
#include <arpa/inet.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Internel functions */

/*
extract ip packet from a whole packet

Args:
  const struct pcap_pkthdr* pkthdr: packet info;
  const u_char* packet: packet actual bytes;
  pcap_stat_offline_t* stat_info: pcap file stat info
*/
void extract_ipv4_pkt(const struct pcap_pkthdr* hdr, const uint8_t* pkt_data,
                      pcap_stat_offline_t* stat_info) {
  uint8_t tl_protocol = pkt_data[ETHERNET_2_HEAD_LEN + 9];
  uint8_t dpkt[DEEP_PACKET_LEN] = {0};
  int min = fmin(hdr->caplen, DEEP_PACKET_LEN);

  if (tl_protocol == TCP_PROTOCOL) {
    (*stat_info).tcp_pkt_num++;

    memcpy(dpkt, pkt_data + ETHERNET_2_HEAD_LEN, min);
  } else if (tl_protocol == UDP_PROTOCOL) {
    (*stat_info).udp_pkt_num++;

    uint8_t pad_buf[12] = {0};
    // copy ipv4 header and upd header
    memcpy(dpkt, pkt_data + ETHERNET_2_HEAD_LEN, IPV4_HEAD_LEN + UDP_HEAD_LEN);
    // copy padding buffer
    memcpy(dpkt + IPV4_HEAD_LEN + UDP_HEAD_LEN, pad_buf, 12);
    // copy udp payload
    memcpy(dpkt + IPV4_HEAD_LEN + UDP_HEAD_LEN + 12,
           pkt_data + ETHERNET_2_HEAD_LEN + IPV4_HEAD_LEN + UDP_HEAD_LEN,
           min - (IPV4_HEAD_LEN + UDP_HEAD_LEN + 12));
  }

  for (int i = 0; i < DEEP_PACKET_LEN; i++) {
    printf("%x ", dpkt[i]);
  }
  printf("\n");
}

/* Public functions */

pcap_stat_offline_t extract_nl_pkt(const char* fname, char* errbuf) {
  pcap_t* descr = pcap_open_offline(fname, errbuf);
  struct pcap_pkthdr* hdr;
  const uint8_t* pkt_data;
  int res;
  pcap_stat_offline_t stat_info = {0};

  printf("Start processing pcap file: %s.\n", fname);
  while ((res = pcap_next_ex(descr, &hdr, &pkt_data)) == 1) {
    stat_info.pkt_num++;
    uint16_t nl_protocol = htons(*(uint16_t*)(pkt_data + 12));
    if (nl_protocol == IPV4_PROTOCOL) {
      extract_ipv4_pkt(hdr, pkt_data, &stat_info);
      stat_info.ip_pkt_num++;
    }
    continue;
  }
  if (res == -1) {
    printf("\nAn error occured while reading pcap file: %s.\n", fname);
    printf("Error info: %s.\n", pcap_geterr(descr));
  }
  printf("\nEnd processing pcap file: %s.", fname);
  printf("\nThere are %llu udp packets in pcap file.", stat_info.udp_pkt_num);

  return stat_info;
}
