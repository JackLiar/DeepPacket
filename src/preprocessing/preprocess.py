# -*- coding: utf-8 -*-

import ctypes
import os
import pathlib
import platform

lib_prep = ctypes.CDLL("./libpreprocess.so")
protocol_dict = {"tcp": 6, "udp": 17}
app_protocol_dict = {
    "youtube": "tcp",
    "tor": "tcp",
    "facebook_audio": "udp",
    "hangouts_audio": "udp"
}


def get_protocol(pcap_fname: str):
  for app in app_protocol_dict.keys():
    if app in pcap_fname:
      return protocol_dict[app_protocol_dict[app]]


def process_pcap(pcap_fname: str, csv_fname: str, protocol: int):
  errbuf = ""
  pcap_fname = ctypes.c_char_p(pcap_fname.encode())
  csv_fname = ctypes.c_char_p(csv_fname.encode())
  protocol = ctypes.c_int(protocol)
  errbuf = ctypes.c_char_p(errbuf.encode())

  lib_prep.extract_pkt(pcap_fname, csv_fname, protocol, errbuf)


if __name__ == "__main__":
  if platform.system() == "Darwin":
    data_path = os.path.expanduser("~/Documents/Codes/Github/DeepPacket/data/")
  elif platform.system() == "Linux":
    data_path = os.path.expanduser("~/code/DeepPacket/data/")

  train_data_path = os.path.join(data_path, "train")
  test_data_path = os.path.join(data_path, "test")

  for file in os.listdir(train_data_path):
    if file.endswith(".pcap") or file.endswith(".pcapng"):
      pcap_fname = os.path.join(train_data_path, file)
      csv_fname = os.path.join(train_data_path, file.split('.')[0] + ".csv")
      process_pcap(pcap_fname, csv_fname, get_protocol(pcap_fname))

  for file in os.listdir(test_data_path):
    if file.endswith(".pcap") or file.endswith(".pcapng"):
      pcap_fname = os.path.join(test_data_path, file)
      csv_fname = os.path.join(test_data_path, file.split('.')[0] + ".csv")
      process_pcap(pcap_fname, csv_fname, get_protocol(pcap_fname))
