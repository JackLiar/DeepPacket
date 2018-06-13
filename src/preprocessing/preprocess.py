# -*- coding: utf-8 -*-

import ctypes
import os
import pathlib
import platform

lib_prep = ctypes.CDLL("./libpreprocess.so")


def process_pcap(pcap_fname: str, csv_fname: str):
  errbuf = ""
  pcap_fname = ctypes.c_char_p(pcap_fname.encode())
  csv_fname = ctypes.c_char_p(csv_fname.encode())
  errbuf = ctypes.c_char_p(errbuf.encode())

  lib_prep.extract_nl_pkt(pcap_fname, csv_fname, errbuf)


if __name__ == "__main__":
  if platform.system() == "Darwin":
    data_path = os.path.join(
        str(pathlib.Path.home()),
        "Documents/Codes/Github/DeepPacket/data/samples/")
  elif platform.system() == "Linux":
    data_path = os.path.join(
        str(pathlib.Path.home()), "/code/DeepPacket/data/samples/")

  for file in os.listdir(data_path):
    if file.endswith(".pcap") or file.endswith(".pcapng"):
      pcap_fname = os.path.join(data_path, file)
      csv_fname = os.path.join(data_path, file.split('.')[0] + ".csv")
      process_pcap(pcap_fname, csv_fname)
