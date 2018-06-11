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
  int min: min of 1500 and packet captured length
*/
void extract_upd_pkt(const uint8_t* pkt_data, uint8_t* dpkt, int min) {
  uint8_t pad_buf[12] = {0};
  // copy ipv4 header and upd header
  memcpy(dpkt, pkt_data + ETHERNET_2_HEAD_LEN, IPV4_HEAD_LEN + UDP_HEAD_LEN);
  // add padding zeros
  memcpy(dpkt + IPV4_HEAD_LEN + UDP_HEAD_LEN, pad_buf, 12);
  // copy udp payload
  memcpy(dpkt + IPV4_HEAD_LEN + UDP_HEAD_LEN + 12,
         pkt_data + ETHERNET_2_HEAD_LEN + IPV4_HEAD_LEN + UDP_HEAD_LEN,
         min - (IPV4_HEAD_LEN + UDP_HEAD_LEN + 12));
}

/*
extract ip packet from a whole packet

Args:
  const struct pcap_pkthdr* pkthdr: packet info;
  const u_char* pdt_data: packet actual bytes;
  pcap_stat_offline_t* stat_info: pcap file stat info
  uint8_t protocol: used to determine extract tcp or udp
*/
ip_pkt_t extract_ipv4_pkt(const struct pcap_pkthdr* hdr,
                          const uint8_t* pkt_data,
                          pcap_stat_offline_t* stat_info, uint8_t protocol) {
  ip_pkt_t ip_pkt = {0, {0}};
  int min = fmin(hdr->caplen, DEEP_PACKET_LEN);

  if (protocol == TCP_PROTOCOL) {
    (*stat_info).tcp_pkt_num++;
    memcpy(ip_pkt.raw, pkt_data + ETHERNET_2_HEAD_LEN, min);
  } else if (protocol == UDP_PROTOCOL) {
    (*stat_info).udp_pkt_num++;
    extract_upd_pkt(pkt_data, ip_pkt.raw, min);
  }
  return ip_pkt;
}

/*
write a processed ip packet to a csv file

Args:
  const char* fname:  csv file name;
  const uint8_t* dpkt: packet to be write;
  int id: packet id in pcap file
*/
int write_pkt_2_csv(const char* fname, const uint8_t* dpkt, int id) {
  FILE* fp = fopen(fname, "a");
  if (!fp) {
    perror("File opening failed");
    return EXIT_FAILURE;
  }

  char record[CSV_ROW_BUF_LEN] = {0};
  char buf[10];

  sprintf(buf, "%d,", id);
  strcat(record, buf);

  for (int i = 0; i < DEEP_PACKET_LEN; i++) {
    if (i == DEEP_PACKET_LEN - 1) {
      sprintf(buf, "%d", dpkt[i]);
    } else {
      sprintf(buf, "%d,", dpkt[i]);
    }
    strcat(record, buf);
  }
  strcat(record, "\n");

  fwrite(record, sizeof(char), strlen(record), fp);
  fclose(fp);
  return 0;
}

/* Public functions */

pcap_stat_offline_t extract_nl_pkt(const char* pcap_fname,
                                   const char* csv_fname, char* errbuf) {
  pcap_t* descr = pcap_open_offline(pcap_fname, errbuf);
  struct pcap_pkthdr* hdr;
  const uint8_t* pkt_data;
  int res;
  pcap_stat_offline_t stat_info = {0};
  uint16_t nl_protocol; /* network layer protocol */
  uint8_t tl_protocol;  /* transport layer protocol */
  ip_pkt_t ip_pkt = {0, {0}};

  int rc = remove(csv_fname);
  if (rc) {
    perror("remove csv file");
    return stat_info;
  }

  printf("Start processing pcap file: %s.\n", pcap_fname);

  while ((res = pcap_next_ex(descr, &hdr, &pkt_data)) == 1) {
    stat_info.pkt_num++;
    nl_protocol = htons(*(uint16_t*)(pkt_data + 12));
    tl_protocol = pkt_data[ETHERNET_2_HEAD_LEN + 9];
    if (nl_protocol == IPV4_PROTOCOL) {
      if (tl_protocol == TCP_PROTOCOL || tl_protocol == UDP_PROTOCOL) {
        ip_pkt = extract_ipv4_pkt(hdr, pkt_data, &stat_info, tl_protocol);
        write_pkt_2_csv(csv_fname, ip_pkt.raw, stat_info.pkt_num);
      }
      stat_info.ip_pkt_num++;
    }
    continue;
  }
  if (res == -1) {
    printf("\nAn error occured while reading pcap file: %s.\n", pcap_fname);
    printf("Error info: %s.\n", pcap_geterr(descr));
  }
  printf("\nEnd processing pcap file: %s.", pcap_fname);

  return stat_info;
}

void print_stat_info(pcap_stat_offline_t stat_info) {
  printf("\nThere are %u ip packets in pcap file.", stat_info.ip_pkt_num);
  printf("\nThere are %u udp packets in pcap file.", stat_info.udp_pkt_num);
  printf("\nThere are %u tcp packets in pcap file.\n", stat_info.tcp_pkt_num);
}