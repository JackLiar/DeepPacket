#include "preprocess.h"
#include "stdlib.h"

#define ERROR_BUF_SIZE 4096

int main(int argc, char* argv[]) {
  if (argc > 0) {
  }
  char* errbuf = (char*)malloc(ERROR_BUF_SIZE * sizeof(char));
  pcap_stat_t stat_info =
      extract_pkt("../../data/samples/youtube2.pcap",
                  "../../data/samples/youtube2.csv", TCP_PROTOCOL, errbuf);
  print_stat_info(stat_info, TCP_PROTOCOL);
}