import torch
import json
from sklearn.metrics import f1_score
from torch_geometric.explain import Explainer, GNNExplainer
from dataset import load_shadowtrace_data
from model import ShadowTraceGNN

data = load_shadowtrace_data('outputs/nodes.csv', 'outputs/edges.csv')
model = ShadowTraceGNN(in_channels=data.x.shape[1], hidden_channels=64)

optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
criterion = torch.nn.BCEWithLogitsLoss(pos_weight=data.pos_weight)

def train():
    model.train()
    optimizer.zero_grad()
    out = model(data.x, data.edge_index)
    loss = criterion(out[data.train_mask], data.y[data.train_mask])
    loss.backward()
    optimizer.step()
    return loss.item()

def test(mask):
    model.eval()
    with torch.no_grad():
        out = model(data.x, data.edge_index)
        preds = torch.sigmoid(out[mask]) > 0.5
        y_true = data.y[mask].cpu().numpy()
        y_pred = preds.cpu().numpy()
        return f1_score(y_true, y_pred, zero_division=0)

# Training Loop
for epoch in range(1, 151):
    loss = train()
    if epoch % 10 == 0:
        val_f1 = test(data.val_mask)
        print(f'Epoch: {epoch:03d}, Loss: {loss:.4f}, Val F1: {val_f1:.4f}')

print(f'Final Test F1-Score: {test(data.test_mask):.4f}')
torch.save(model.state_dict(), 'shadowtrace.pt')
print("Model weights saved to shadowtrace.pt")

# XAI Integration API Export
print("Extracting feature attributions via GNNExplainer...")
explainer = Explainer(
    model=model,
    algorithm=GNNExplainer(epochs=50),
    explanation_type='model',
    node_mask_type='attributes',
    edge_mask_type='object',
    model_config=dict(
        mode='binary_classification',
        task_level='node',
        return_type='raw',
    )
)

# Extract rules for a sample illicit node and export to JSON for backend usage
illicit_nodes = (data.y == 1).nonzero(as_tuple=True)[0]
sample_node = illicit_nodes[0].item()
explanation = explainer(data.x, data.edge_index, index=sample_node)

xai_payload = {
    "target_node": sample_node,
    "feature_weights": explanation.node_mask.mean(dim=0).tolist()
}

with open('outputs/xai_sample.json', 'w') as f:
    json.dump(xai_payload, f)
print("XAI weights exported to outputs/xai_sample.json")