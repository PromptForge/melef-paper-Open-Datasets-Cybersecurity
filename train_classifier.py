import os
import urllib.parse
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold, GroupShuffleSplit
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# -------------------------------------------------------------
# Configuration aligned with Manuscript electronics-4565560
# -------------------------------------------------------------
RANDOM_STATE = 42
N_ESTIMATORS = 100
MAX_DEPTH = 15
MIN_SAMPLES_SPLIT = 5

def extract_15_features(url_string):
    """
    Extracts the exact 15 features defined in Table 4 of the manuscript:
    - Lexical (9): url_len, special_., special_-, special_/, special_=, special_?, special_&, special_@, has_login
    - Domain (3): hostname_len, subdomain_count, tld_len
    - Path (3): path_len, path_levels, has_exe
    """
    if not isinstance(url_string, str):
        url_string = str(url_string)
        
    if not url_string.startswith(('http://', 'https://')):
        url_string = 'http://' + url_string
        
    parsed = urllib.parse.urlparse(url_string)
    hostname = parsed.netloc.split(':')[0]
    path = parsed.path
    
    # Lexical features
    url_len = len(url_string)
    dot_count = url_string.count('.')
    hyphen_count = url_string.count('-')
    slash_count = url_string.count('/')
    equal_count = url_string.count('=')
    question_count = url_string.count('?')
    amp_count = url_string.count('&')
    at_count = url_string.count('@')
    has_login = 1 if 'login' in url_string.lower() else 0
    
    # Domain-based features
    hostname_len = len(hostname)
    subdomain_count = max(0, hostname.count('.') - 1) if hostname else 0
    tld_parts = hostname.rsplit('.', 1)
    tld_len = len(tld_parts[1]) if len(tld_parts) > 1 else 0
    
    # Path-based features
    path_len = len(path)
    path_levels = len([p for p in path.split('/') if p])
    has_exe = 1 if '.exe' in path.lower() else 0
    
    return [
        url_len, dot_count, hyphen_count, slash_count, equal_count, 
        question_count, amp_count, at_count, has_login,
        hostname_len, subdomain_count, tld_len,
        path_len, path_levels, has_exe
    ]

def evaluate_pipeline(X, y, groups):
    """
    Executes domain-level 80/20 train-test split, 10-fold CV on train,
    and out-of-sample evaluation on held-out test set.
    """
    gss = GroupShuffleSplit(n_splits=1, train_size=0.8, random_state=RANDOM_STATE)
    train_idx, test_idx = next(gss.split(X, y, groups))
    
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    groups_train = groups[train_idx]
    
    # 1. 10-fold Grouped CV on Train Partition
    sgkf = StratifiedGroupKFold(n_splits=10)
    rf = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        min_samples_split=MIN_SAMPLES_SPLIT,
        random_state=RANDOM_STATE
    )
    
    cv_scores = []
    for f_train, f_val in sgkf.split(X_train, y_train, groups_train):
        rf.fit(X_train[f_train], y_train[f_train])
        preds = rf.predict(X_train[f_val])
        cv_scores.append(accuracy_score(y_train[f_val], preds))
        
    print(f"10-fold CV Mean Accuracy: {np.mean(cv_scores)*100:.1f}% (+/- {np.std(cv_scores)*100:.1f}%)")
    
    # 2. Held-out Test Set Evaluation
    rf.fit(X_train, y_train)
    test_preds = rf.predict(X_test)
    print(f"Held-out Test Accuracy: {accuracy_score(y_test, test_preds)*100:.1f}%")
    print(f"Phishing Precision: {precision_score(y_test, test_preds, pos_label=1)*100:.1f}%")
    print(f"Phishing Recall: {recall_score(y_test, test_preds, pos_label=1)*100:.1f}%")
    print(f"Phishing F1-Score: {f1_score(y_test, test_preds, pos_label=1)*100:.1f}%")
    print(f"Benign Precision: {precision_score(y_test, test_preds, pos_label=0)*100:.1f}%")
    print(f"Benign Recall: {recall_score(y_test, test_preds, pos_label=0)*100:.1f}%")
    print(f"Benign F1-Score: {f1_score(y_test, test_preds, pos_label=0)*100:.1f}%")
    
    # 3. Logistic Regression Baseline
    lr = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)
    lr.fit(X_train, y_train)
    lr_preds = lr.predict(X_test)
    print(f"Logistic Regression Test Accuracy: {accuracy_score(y_test, lr_preds)*100:.1f}%")
    return rf

def run_from_data():
    csv_candidates = ['dataset.csv', 'urls.csv', 'data/dataset.csv']
    dataset_path = None
    for p in csv_candidates:
        if os.path.exists(p):
            dataset_path = p
            break
            
    if dataset_path:
        df = pd.read_csv(dataset_path)
        url_col = [c for c in df.columns if 'url' in c.lower()][0]
        label_col = [c for c in df.columns if 'label' in c.lower()][0]
        
        X = np.array([extract_15_features(u) for u in df[url_col]])
        y = np.array(df[label_col].values)
        groups = np.array([urllib.parse.urlparse(u if u.startswith('http') else 'http://'+u).netloc.split(':')[0] for u in df[url_col]])
        
        print(f"Loaded {len(df)} samples from {dataset_path}. Executing evaluation...")
        evaluate_pipeline(X, y, groups)
    else:
        print("MELEF Research Pipeline initialized. Ready to evaluate upon providing dataset.csv.")

if __name__ == "__main__":
    run_from_data()
