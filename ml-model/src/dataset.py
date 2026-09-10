import pandas as pd
import torch
from torch_geometric.data import Data

def load_shadowtrace_data(nodes_path='outputs/nodes.csv', edges_path='outputs/edges.csv'):
    nodes_df = pd.read_csv(nodes_path)
    edges_df = pd.read_csv(edges_path)

    # Isolate feature matrix by explicitly dropping non-feature columns
    drop_cols = ['txId', 'class', 'time_step']
    feature_cols = [c for c in nodes_df.columns if c not in drop_cols]
    
    x = torch.tensor(nodes_df[feature_cols].values, dtype=torch.float)
    y = torch.tensor(nodes_df['class'].values, dtype=torch.float)

    # Construct edge index using integer mapping
    node_mapping = {tx: i for i, tx in enumerate(nodes_df['txId'].values)}
    src = [node_mapping[tx] for tx in edges_df['source'] if tx in node_mapping]
    dst = [node_mapping[tx] for tx in edges_df['target'] if tx in node_mapping]
    edge_index = torch.tensor([src, dst], dtype=torch.long)

    # Inductive splitting explicitly based on time steps, ignoring unknown (-1) labels
    time_steps = nodes_df['time_step'].values
    train_mask = torch.tensor((time_steps <= 34) & (y.numpy() != -1), dtype=torch.bool)
    val_mask = torch.tensor((time_steps > 34) & (time_steps <= 42) & (y.numpy() != -1), dtype=torch.bool)
    test_mask = torch.tensor((time_steps > 42) & (y.numpy() != -1), dtype=torch.bool)

    # Calculate BCEWithLogitsLoss imbalance penalty based strictly on the training set
    num_pos = (y[train_mask] == 1).sum().item()
    num_neg = (y[train_mask] == 0).sum().item()
    pos_weight = torch.tensor([num_neg / num_pos], dtype=torch.float) if num_pos > 0 else torch.tensor([1.0])

    data = Data(x=x, edge_index=edge_index, y=y)
    data.train_mask = train_mask
    data.val_mask = val_mask
    data.test_mask = test_mask
    data.pos_weight = pos_weight

    return data