import pandas as pd

files = ["CEAS_08.csv", "Enron.csv", "Ling.csv", "SpamAssasin.csv", "phishing_email.csv"]

for path in files:
    df = pd.read_csv(path, encoding_errors="replace", on_bad_lines="skip", low_memory=False)
    print("=" * 60, path)
    if "subject" not in df.columns:
        print("(no subject column; showing first 80 chars of text_combined)")
        col = "text_combined"
        show = lambda s: str(s)[:80]
    else:
        col = "subject"
        show = lambda s: str(s)[:80]
    for lbl in sorted(df["label"].unique()):
        print(f"-- label {lbl}")
        for s in df[df["label"] == lbl][col].dropna().sample(3, random_state=1):
            print("   ", show(s))