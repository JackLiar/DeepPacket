#include "extract_packet.h"
#include "stdlib.h"

#define ERROR_BUF_SIZE 4096

int main(int argc, char* argv[]) {
  if (argc > 0) {
  }
  char* errbuf = (char*)malloc(ERROR_BUF_SIZE * sizeof(char));
  pcap_stat_offline_t stat_info =
      extract_nl_pkt("../../data/samples/scpDown5.pcap",
                     "../../data/samples/scpDown5.csv", errbuf);
  print_stat_info(stat_info);
}