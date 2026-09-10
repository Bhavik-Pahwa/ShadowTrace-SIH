import sqlite3
import torch
import pandas as pd
from dataset import load_shadowtrace_data
from model import ShadowTraceGNN

# 1. Load the original data and the trained model
data = load_shadowtrace_data('outputs/nodes.csv', 'outputs/edges.csv')
model = ShadowTraceGNN(in_channels=data.x.shape[1], hidden_channels=64)
model.load_state_dict(torch.load('shadowtrace.pt'))
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

# 2. Extract Human Feedback from SQLite
conn = sqlite3.connect("feedback.db")
feedback_df = pd.read_sql_query("SELECT tx_id, human_label FROM feedback", conn)
conn.close()

if not feedback_df.empty:
    print(f"Applying {len(feedback_df)} investigator corrections...")
    nodes_df = pd.read_csv('outputs/nodes.csv')
    
    # 3. Patch the dataset labels dynamically
    for _, row in feedback_df.iterrows():
        # Find the integer index of the tx_id in the graph
        node_idx = nodes_df.index[nodes_df['txId'] == int(row['tx_id'])].tolist()[0]
        # Update the ground truth label in the PyTorch tensor
        data.y[node_idx] = row['human_label']
        # Add to training mask so the model explicitly learns from this node
        data.train_mask[node_idx] = True

    # 4. Fine-Tune the Model
    model.train()
    criterion = torch.nn.BCEWithLogitsLoss()
    
    print("Fine-tuning model weights...")
    for epoch in range(20):  # Short loop for demo purposes
        optimizer.zero_grad()
        out = model(data.x, data.edge_index)
        loss = criterion(out[data.train_mask], data.y[data.train_mask])
        loss.backward()
        optimizer.step()

    # 5. Export Model v2
    torch.save(model.state_dict(), 'shadowtrace_v2.pt')
    print("Success: Model v2 saved! The AI has learned from the human feedback.")
else:
    print("No human feedback found in database. Skipping retraining.")