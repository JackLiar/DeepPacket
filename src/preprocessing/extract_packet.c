#include "extract_packet.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Internel functions */

/*
extract ip packet from a whole packet

Args:
  const struct pcap_pkthdr* pkthdr: packet info;
  const u_char* packet: packet actual bytes
*/
void hnd_extract_ip_pkt(const struct pcap_pkthdr* pkthdr,
                        const uint8_t* packet) {
  // Ethernet II protocol's head is 12 bytes
  for (int i = 12; i < pkthdr->caplen; i++) {
  }
}

/* Public functions */

struct pcap_stat_offline extract_ip_pkt(const char* fname, char* errbuf) {
  pcap_t* descr = pcap_open_offline(fname, errbuf);
  struct pcap_pkthdr* hdr;
  const uint8_t* pkt_data;
  int res;
  struct pcap_stat_offline stat_info = {0};

  while ((res = pcap_next_ex(descr, &hdr, &pkt_data)) == 1) {
    if (res == 1) {
      stat_info.pkt_num++;
      printf("%d;", stat_info.pkt_num);
      continue;
    }
    if (res == -1) {
      printf("An error occured while reading pcap file: %s.\n", fname);
      printf("Error info: %s\n", pcap_geterr(descr));
    }
  }
  printf("End reading pcap file: %s.", fname);
}
