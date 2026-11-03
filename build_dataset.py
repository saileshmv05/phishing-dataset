
import pandas as pd

FILES = [
    "CEAS_08.csv",
    "Enron.csv",
    "Ling.csv",
    "SpamAssasin.csv",
    "Nazario.csv",
    "emails.csv",
    "phishing_email.csv",
]

def load(path):
    df = pd.read_csv(path, encoding_errors="replace", on_bad_lines="skip", low_memory=False)
    if "text_combined" in df.columns:
        text = df["text_combined"].fillna("").astype(str)
    else:
        subject = df["subject"].fillna("").astype(str)
        body = df["body"].fillna("").astype(str)
        text = subject + " " + body
    return pd.DataFrame({
        "text": text.str.strip(),
        "label": df["label"].astype(int),
        "source": path.replace(".csv", ""),
    })

df = pd.concat([load(f) for f in FILES], ignore_index=True)
print("Raw rows:", len(df))

# Drop very short texts (empty or near-empty emails)
df = df[df["text"].str.len() > 20].copy()

# Normalize for duplicate detection
df["norm"] = df["text"].str.lower().str.replace(r"\s+", " ", regex=True).str.strip()

# Remove texts that appear with conflicting labels
conflict = df.groupby("norm")["label"].nunique()
conflicting = conflict[conflict > 1].index
df = df[~df["norm"].isin(conflicting)]

# Remove exact duplicates across all sources
df = df.drop_duplicates(subset=["norm"])
df = df.drop(columns=["norm"])

df.to_csv("dataset.csv", index=False)

print("After cleaning:", len(df))
print(df["label"].value_counts())
print(df["source"].value_counts())