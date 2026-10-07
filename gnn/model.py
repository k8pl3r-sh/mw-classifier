#!/usr/bin/python3

"""
Graph Isomorphism Network (GIN) for graph-level malware family classification.

torch / torch_geometric are imported at module level, so this module must only
be imported when the GNN is actually used (it is not auto-loaded anywhere).
"""

import torch
import torch.nn.functional as F
from torch.nn import Linear, Sequential, ReLU, BatchNorm1d
from torch_geometric.nn import GINConv, global_mean_pool


class GIN(torch.nn.Module):
    def __init__(self, in_dim: int, hidden: int, n_classes: int, n_layers: int = 3, dropout: float = 0.5):
        super().__init__()
        self.dropout = dropout
        self.convs = torch.nn.ModuleList()
        dims = [in_dim] + [hidden] * n_layers
        for a, b in zip(dims[:-1], dims[1:]):
            mlp = Sequential(Linear(a, b), BatchNorm1d(b), ReLU(), Linear(b, b), ReLU())
            self.convs.append(GINConv(mlp))
        self.lin1 = Linear(hidden, hidden)
        self.lin2 = Linear(hidden, n_classes)

    def forward(self, x, edge_index, batch):
        for conv in self.convs:
            x = F.relu(conv(x, edge_index))
        x = global_mean_pool(x, batch)          # graph-level embedding
        x = F.relu(self.lin1(x))
        x = F.dropout(x, p=self.dropout, training=self.training)
        return self.lin2(x)
