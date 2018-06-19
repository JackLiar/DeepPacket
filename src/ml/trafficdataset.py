import numpy as np
import os
import torch
from torch.utils.data import DataLoader, Dataset


def iter_loadcsv(filename: str, n_samples, delimiter=',', dtype=float):
  '''
  loda traffic csv file

  source code: https://stackoverflow.com/questions/8956832/python-out-of-memory-on-large-csv-file-numpy

  Returns:
    data(troch.Tensor): first column is id, 1:1501(1001) is byte data
  '''

  def iter_func():
    with open(filename, 'r') as infile:
      count = 0
      for line in infile:
        line = line.rstrip().split(delimiter)
        if count == n_samples:
          break
        count = count + 1
        for i, item in enumerate(line):
          if not i == 0:
            yield dtype(item)
          else:
            yield dtype(item)
    iter_loadcsv.rowlength = len(line)

  data = np.fromiter(iter_func(), dtype=dtype)
  data = data.reshape((-1, iter_loadcsv.rowlength))
  data = torch.from_numpy(data).float()
  index = data[:, 0]
  data[:, 1:] = data[:, 1:] / 255
  return data, index


class TrafficDataset(Dataset):

  def __init__(self, src_dir: str, n_samples=5000):
    self.data = torch.empty((0, 1501))
    self.data_index_dict = {}
    for file in os.listdir(src_dir):
      if file.endswith(".csv"):
        file_abs = os.path.abspath(os.path.join(src_dir, file))
        print("loading", file, "...")
        data, self.data_index_dict[file] = iter_loadcsv(file_abs, n_samples)
        self.data = torch.cat((self.data, data))

  def __getitem__(self, index):
    return self.data[index, 1:]

  def __len__(self):
    return len(self.data)
