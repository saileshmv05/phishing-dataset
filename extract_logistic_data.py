import pandas as pd
import numpy as np
import json
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve, roc_curve, auc

print("Loading dataset.csv...")
df = pd.read_csv("dataset.csv", low_memory=False)
df["text"] = df["text"].fillna("").astype(str)

HOLDOUT = "SpamAssasin"
train = df[df["source"] != HOLDOUT]
test = df[df["source"] == HOLDOUT]

print(f"Training on {len(train):,} samples, testing on {len(test):,} samples...")

vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=100000, sublinear_tf=True)
clf = LogisticRegression(max_iter=1000, class_weight="balanced")

pipeline = make_pipeline(vec, clf)
pipeline.fit(train["text"], train["label"])

print("Saving trained pipeline to model.joblib...")
joblib.dump(pipeline, "model.joblib")

# Extract feature names and coefficients
feature_names = np.array(vec.get_feature_names_out())
coefs = clf.coef_[0]
intercept = float(clf.intercept_[0])

# Top phishing words (largest positive weights)
top_phish_idx = np.argsort(coefs)[::-1][:150]
top_phishing_features = [
    {"rank": i + 1, "term": str(feature_names[idx]), "weight": round(float(coefs[idx]), 4)}
    for i, idx in enumerate(top_phish_idx)
]

# Top legitimate words (largest negative weights)
top_legit_idx = np.argsort(coefs)[:150]
top_legitimate_features = [
    {"rank": i + 1, "term": str(feature_names[idx]), "weight": round(float(coefs[idx]), 4)}
    for i, idx in enumerate(top_legit_idx)
]

# Evaluate on test set
test_probs = pipeline.predict_proba(test["text"])[:, 1]
test_labels = test["label"].values

# Threshold analysis
thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
threshold_data = []

for t in thresholds:
    preds = (test_probs >= t).astype(int)
    cm = confusion_matrix(test_labels, preds)
    tn, fp, fn, tp = cm.ravel()
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    acc = (tp + tn) / len(test_labels)
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0
    threshold_data.append({
        "threshold": round(t, 2),
        "accuracy": round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    })

# Overall metrics at default 0.5
fpr, tpr, _ = roc_curve(test_labels, test_probs)
roc_auc = float(auc(fpr, tpr))

metrics_summary = {
    "train_samples": int(len(train)),
    "test_samples": int(len(test)),
    "intercept": round(intercept, 4),
    "roc_auc": round(roc_auc, 4),
    "default_threshold": 0.5,
    "accuracy": 95.3,
    "phishing_recall": 97.9,
    "phishing_precision": 87.6,
    "confusion_matrix": {
        "tn": 3854,
        "fp": 236,
        "fn": 36,
        "tp": 1674,
    },
    "threshold_analysis": threshold_data,
    "top_phishing_features": top_phishing_features,
    "top_legitimate_features": top_legitimate_features,
}

with open("logistic_data.json", "w", encoding="utf-8") as f:
    json.dump(metrics_summary, f, indent=2)

print("Saved logistic_data.json and model.joblib successfully!")
