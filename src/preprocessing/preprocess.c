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
void extract_udp_pkt(const uint8_t* pkt_data, uint8_t* dpkt, int min) {
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
int extract_ipv4_pkt(const struct pcap_pkthdr* hdr, const uint8_t* pkt_data,
                     pcap_stat_offline_t* stat_info, ip_pkt_t* ip_pkt,
                     uint8_t protocol) {
  (*ip_pkt).id = 0;
  memset((*ip_pkt).raw, 0, DEEP_PACKET_LEN);
  int min = fmin(hdr->caplen, DEEP_PACKET_LEN);

  if (protocol == TCP_PROTOCOL) {
    (*stat_info).tcp_pkt_num++;
#ifdef NO_EMPTY_PAYLOAD
    uint8_t tcp_header_len =
        4 * (*(pkt_data + ETHERNET_2_HEAD_LEN + IPV4_HEAD_LEN + 12) >> 4);
    uint8_t all_header_len =
        ETHERNET_2_HEAD_LEN + IPV4_HEAD_LEN + tcp_header_len;
    if ((hdr->caplen - all_header_len) == 0) {
      return 0;
    }
#endif
    memcpy((*ip_pkt).raw, pkt_data + ETHERNET_2_HEAD_LEN, min);
  } else if (protocol == UDP_PROTOCOL) {
    (*stat_info).udp_pkt_num++;
    extract_udp_pkt(pkt_data, (*ip_pkt).raw, min);
  }
  return 1;
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

  remove(csv_fname);

  printf("Start processing pcap file: %s.\n", pcap_fname);

  while ((res = pcap_next_ex(descr, &hdr, &pkt_data)) == 1) {
    stat_info.pkt_num++;
    nl_protocol = htons(*(uint16_t*)(pkt_data + 12));
    tl_protocol = pkt_data[ETHERNET_2_HEAD_LEN + 9];
    if (nl_protocol == IPV4_PROTOCOL) {
      stat_info.ip_pkt_num++;
      if (tl_protocol == TCP_PROTOCOL || tl_protocol == UDP_PROTOCOL) {
        int valid =
            extract_ipv4_pkt(hdr, pkt_data, &stat_info, &ip_pkt, tl_protocol);
#ifdef NO_EMPTY_PAYLOAD
        if (!valid) {
          continue;
        }
#endif
        write_pkt_2_csv(csv_fname, ip_pkt.raw, stat_info.pkt_num);
      }
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