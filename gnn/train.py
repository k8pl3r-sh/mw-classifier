#!/usr/bin/python3

"""
Train and evaluate the GIN on the call-graph dataset (graph-level family
classification). Imports torch lazily inside run_gnn so the rest of the project
never depends on it.
"""

from collections import Counter

from utils.logger import Log
from gnn.graph_builder import build_dataset, NODE_FEATURE_DIM


def run_gnn(samples_dir: str, epochs: int = 150, hidden: int = 64,
            test_size: float = 0.3, seed: int = 42) -> None:
    log = Log("GNN")

    import numpy as np
    import torch
    from torch_geometric.data import Data
    from torch_geometric.loader import DataLoader
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, f1_score
    from gnn.model import GIN

    torch.manual_seed(seed)
    np.random.seed(seed)

    raw = build_dataset(samples_dir, log)
    if not raw:
        log.error("No graphs built (need PE binaries + capstone/pefile). Aborting.")
        return

    # Drop singleton families: a graph-classification model cannot learn a class
    # it has only seen once (and stratified splitting needs >= 2 per class).
    family_counts = Counter(g["family"] for g in raw)
    kept = [g for g in raw if family_counts[g["family"]] >= 2]
    dropped = len(raw) - len(kept)
    if len(kept) < 4 or len({g["family"] for g in kept}) < 2:
        log.error("Not enough non-singleton samples/classes to train. Aborting.")
        return

    families = sorted({g["family"] for g in kept})
    label_of = {fam: i for i, fam in enumerate(families)}

    data_list = []
    for g in kept:
        data_list.append(Data(
            x=torch.tensor(g["x"], dtype=torch.float),
            edge_index=torch.tensor(g["edge_index"], dtype=torch.long),
            y=torch.tensor([label_of[g["family"]]], dtype=torch.long),
        ))

    y_all = [label_of[g["family"]] for g in kept]
    train_idx, test_idx = train_test_split(
        range(len(data_list)), test_size=test_size, random_state=seed, stratify=y_all
    )
    train_set = [data_list[i] for i in train_idx]
    test_set = [data_list[i] for i in test_idx]

    # drop_last avoids a size-1 final batch breaking BatchNorm during training.
    train_loader = DataLoader(train_set, batch_size=16, shuffle=True, drop_last=len(train_set) > 16)
    test_loader = DataLoader(test_set, batch_size=32, shuffle=False)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = GIN(in_dim=NODE_FEATURE_DIM, hidden=hidden, n_classes=len(families)).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)
    criterion = torch.nn.CrossEntropyLoss()

    log.info(f"Training GIN on {len(train_set)} graphs, testing on {len(test_set)}, "
             f"{len(families)} families, {dropped} singleton samples dropped.")

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            out = model(batch.x, batch.edge_index, batch.batch)
            loss = criterion(out, batch.y)
            loss.backward()
            optimizer.step()
            total_loss += float(loss)
        if epoch % 25 == 0 or epoch == 1:
            log.info(f"epoch {epoch:>3} loss={total_loss / max(1, len(train_loader)):.4f}")

    model.eval()
    y_true, y_pred = [], []
    with torch.no_grad():
        for batch in test_loader:
            batch = batch.to(device)
            pred = model(batch.x, batch.edge_index, batch.batch).argmax(dim=1)
            y_true.extend(batch.y.tolist())
            y_pred.extend(pred.tolist())

    accuracy = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)

    print(_render(len(kept), dropped, len(families), len(train_set), len(test_set), accuracy, macro_f1))


def _render(n_kept, dropped, n_families, n_train, n_test, accuracy, macro_f1) -> str:
    sep = "=" * 70
    lines = [
        sep,
        "  GNN (GIN on call graph) — graph-level family classification",
        sep,
        f"  Graphs (non-singleton)  : {n_kept}  ({dropped} singleton samples dropped)",
        f"  Families                : {n_families}",
        f"  Train / Test            : {n_train} / {n_test}",
        f"  Test accuracy           : {accuracy * 100:.1f}%",
        f"  Test macro-F1           : {macro_f1:.3f}",
        sep,
        "  Note: tiny dataset — expect high variance and overfitting. This",
        "  pipeline is built to scale to a larger corpus; treat APT1 numbers",
        "  as a smoke test, not a verdict.",
        sep,
    ]
    return "\n".join(lines)
