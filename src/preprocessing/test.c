#include "extract_packet.h"
#include "stdlib.h"

#define ERROR_BUF_SIZE 4096

int main(int argc, char* argv[]) {
  if (argc > 0) {
  }
  char* errbuf = malloc(ERROR_BUF_SIZE * sizeof(char));
  extract_nl_pkt("./test.pcap", errbuf);
}