import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.metrics import classification_report, confusion_matrix

df = pd.read_csv("dataset.csv", low_memory=False)
df["text"] = df["text"].fillna("").astype(str)

# The whole source is held out for testing. It must contain both classes.
HOLDOUT = "SpamAssasin"

train = df[df["source"] != HOLDOUT]
test = df[df["source"] == HOLDOUT]

print("Train:", len(train), "| Test:", len(test))

model = make_pipeline(
    TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=100000, sublinear_tf=True),
    LogisticRegression(max_iter=1000, class_weight="balanced"),
)
model.fit(train["text"], train["label"])

preds = model.predict(test["text"])
print(classification_report(test["label"], preds, digits=3))
print(confusion_matrix(test["label"], preds))