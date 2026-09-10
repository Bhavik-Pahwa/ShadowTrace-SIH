import torch
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv

class ShadowTraceGNN(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels, out_channels=1):
        super(ShadowTraceGNN, self).__init__()
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, hidden_channels)
        self.conv3 = SAGEConv(hidden_channels, out_channels)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=0.4, training=self.training)
        
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=0.4, training=self.training)
        
        x = self.conv3(x, edge_index)
        return x.squeeze()