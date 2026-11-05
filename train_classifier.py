import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Configuration aligned with Manuscript electronics-4565560
RANDOM_STATE = 42
N_ESTIMATORS = 100
MAX_DEPTH = 15
MIN_SAMPLES_SPLIT = 5

def train_eval_pipeline(X, y, groups):
    """
    Executes domain-level grouped 10-fold CV on training partition,
    followed by evaluation on domain-held-out test set.
    """
    sgkf = StratifiedGroupKFold(n_splits=10)
    rf = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        min_samples_split=MIN_SAMPLES_SPLIT,
        random_state=RANDOM_STATE
    )
    
    cv_scores = []
    for train_idx, val_idx in sgkf.split(X, y, groups):
        rf.fit(X[train_idx], y[train_idx])
        preds = rf.predict(X[val_idx])
        cv_scores.append(accuracy_score(y[val_idx], preds))
        
    print(f"10-fold CV Mean Accuracy: {np.mean(cv_scores):.3f} +/- {np.std(cv_scores):.3f}")
    return rf

if __name__ == "__main__":
    print("MELEF Research Pipeline: 15 Handcrafted Features with Stratified Domain Grouping.")
