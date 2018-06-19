import os
import platform
import time

import numpy as np
import sklearn.cluster as cluster
import torch
from torch.utils.data import DataLoader

from trafficdataset import TrafficDataset
from models import AutoEncoder, StackedAutoEncoder

if platform.system() == "Darwin":
  data_path = os.path.expanduser("~/Documents/Codes/Github/DeepPacket/data/")
elif platform.system() == "Linux":
  data_path = os.path.expanduser("~/code/DeepPacket/data/")

train_dataset = TrafficDataset(os.path.join(data_path, "train"), 8000)
test_dataset = TrafficDataset(os.path.join(data_path, "test"), 1000)

train_dataloader = DataLoader(train_dataset, batch_size=1000, shuffle=True)
test_dataloader = DataLoader(test_dataset, batch_size=1000, shuffle=True)

n_clusters = 4
n_samples = 1000
epochs = 50

sae = StackedAutoEncoder()

print("training Stack Autoencoder, epochs", epochs, "...")
for i in range(epochs):
  total_time = time.time()
  sae.train()
  for j, data in enumerate(train_dataloader):
    sae(data)

  sae.eval()
  features, reconstruct = sae(train_dataset.data[:, 1:])
  reconstruct_loss = torch.mean((train_dataset.data[:, 1:] - reconstruct)**2)
  print("epoch:", i, ",time usage:",
        time.time() - total_time, "reconstruct loss:", reconstruct_loss)

print("extracting features...")
train_features, _ = sae(train_dataset.data[:, 1:].detach())
test_features, _ = sae(test_dataset.data[:, 1:].detach())

print("clustering...")
ward_cluster = cluster.AgglomerativeClustering(n_clusters)
ward_cluster.fit(train_features.numpy())
result = ward_cluster.fit_predict(test_features.numpy())

for i, csv in enumerate(test_dataset.data_index_dict.keys()):
  print("-" * 20)
  print(csv, "cluster status:")
  for j in range(n_clusters):
    print(np.sum(result[n_samples * i:n_samples * (i + 1)] == j))
