import os
import json
import re
import webbrowser
from threading import Timer
import pandas as pd
import numpy as np
import joblib
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_FILE = os.path.join(BASE_DIR, "dataset.csv")
LOGISTIC_DATA_FILE = os.path.join(BASE_DIR, "logistic_data.json")
MODEL_FILE = os.path.join(BASE_DIR, "model.joblib")

# Global cached data
cached_logistic_data = None
cached_model = None
cached_df = None


def get_logistic_data():
    global cached_logistic_data
    if cached_logistic_data is None and os.path.exists(LOGISTIC_DATA_FILE):
        with open(LOGISTIC_DATA_FILE, "r", encoding="utf-8") as f:
            cached_logistic_data = json.load(f)
    return cached_logistic_data


def get_model():
    global cached_model
    if cached_model is None and os.path.exists(MODEL_FILE):
        cached_model = joblib.load(MODEL_FILE)
    return cached_model


def get_df():
    global cached_df
    if cached_df is None and os.path.exists(DATASET_FILE):
        cached_df = pd.read_csv(DATASET_FILE, low_memory=False)
        cached_df["text"] = cached_df["text"].fillna("").astype(str)
    return cached_df


class IntelligentThreatAnalyzer:
    """Multi-factor semantic & behavioral analyzer to eliminate false alarms."""

    URGENCY_PATTERNS = [
        r"\b(?:within\s+\d+\s+(?:hours?|days?|minutes?)|immediately|urgent(?:ly)?|action\s+required)\b",
        r"\b(?:account\s+suspended|access\s+blocked|security\s+alert|unauthorized\s+access)\b",
        r"\b(?:verify\s+your\s+(?:identity|account|credentials|password|pin))\b",
        r"\b(?:fail(?:ure)?\s+to\s+respond|legal\s+action|permanently\s+closed)\b",
    ]

    SUSPICIOUS_LINK_PATTERNS = [
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"https?://[^/\s]+(?:-[^/\s]+){2,}",
        r"\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly)\b",
        r"\.(?:xyz|top|work|tk|ml|ga|cf|gq|buzz|click)(?:/|\s|$)",
    ]

    LEGIT_CONTEXT_PATTERNS = [
        r"\b(?:agenda|meeting\s+minutes|quarterly|schedule\s+attached|presentation\s+slides)\b",
        r"\b(?:attached\s+(?:report|file|invoice|pdf|spreadsheet)|regards|sincerely)\b",
        r"\b(?:team|colleagues|project\s+milestone|discussion\s+thread|office\s+memo)\b",
    ]

    @classmethod
    def analyze(cls, text, ml_prob_phish, top_tokens=None):
        text_lower = text.lower()
        findings = []

        # 1. Psychological Urgency / Threat Trigger Check
        urgency_matches = []
        for p in cls.URGENCY_PATTERNS:
            found = re.findall(p, text_lower)
            if found:
                urgency_matches.extend(found)
        urgency_score = min(1.0, len(urgency_matches) * 0.35)

        # 2. Structural & Hyperlink Risk Check
        link_matches = []
        for p in cls.SUSPICIOUS_LINK_PATTERNS:
            found = re.findall(p, text_lower)
            if found:
                link_matches.extend(found)
        urls = re.findall(r"https?://[^\s]+", text_lower)
        url_count = len(urls)
        link_risk_score = 0.0
        if link_matches:
            link_risk_score = 0.90
            findings.append(f"Suspicious URL anomaly detected: {', '.join(link_matches[:2])}")
        elif url_count > 3:
            link_risk_score = 0.50
            findings.append(f"High link density detected ({url_count} links)")

        # 3. Safe Conversational Context (Mitigation)
        legit_matches = []
        for p in cls.LEGIT_CONTEXT_PATTERNS:
            found = re.findall(p, text_lower)
            if found:
                legit_matches.extend(found)
        safe_context_detected = len(legit_matches) > 0 and len(link_matches) == 0

        # Intelligent Combined Probability Adjustment
        adjusted_prob = ml_prob_phish
        mitigated = False

        if safe_context_detected and urgency_score < 0.3:
            mitigation_factor = 0.42
            adjusted_prob = ml_prob_phish * mitigation_factor
            mitigated = True
            findings.append(f"Safe corporate/academic context detected ({', '.join(legit_matches[:2])}) - mitigated false alarm.")
        elif urgency_score > 0.5 or link_risk_score > 0.5:
            adjusted_prob = max(ml_prob_phish, min(100.0, ml_prob_phish + 15.0))
            if urgency_matches:
                findings.append(f"High urgency coercion cue: '{urgency_matches[0]}'")

        return {
            "raw_ml_prob": round(float(ml_prob_phish), 2),
            "adjusted_prob": round(float(adjusted_prob), 2),
            "urgency_level": "High" if urgency_score > 0.5 else ("Medium" if urgency_score > 0.2 else "Low"),
            "urgency_score": round(urgency_score * 100, 1),
            "link_risk": "High Anomaly" if link_risk_score > 0.7 else ("Medium" if link_risk_score > 0.3 else "Clean / Low"),
            "link_risk_score": round(link_risk_score * 100, 1),
            "safe_context": "Detected (Mitigated)" if safe_context_detected else "None",
            "mitigated": mitigated,
            "findings": findings,
            "is_phishing": bool(adjusted_prob >= 50.0),
        }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    logistic_data = get_logistic_data()
    return jsonify({
        "status": "success",
        "data": logistic_data
    })


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json() or {}
    text = data.get("text", "").strip()
    subject = data.get("subject", "").strip()

    full_text = f"{subject} {text}".strip()
    if not full_text:
        return jsonify({"status": "error", "message": "Email text is required"}), 400

    model = get_model()
    if model is None:
        return jsonify({"status": "error", "message": "Model not loaded"}), 500

    # ML Inference
    probs = model.predict_proba([full_text])[0]
    raw_phish_prob = float(probs[1] * 100)

    # Word contribution extraction
    vec = model.named_steps["tfidfvectorizer"]
    clf = model.named_steps["logisticregression"]
    words = re.findall(r"\b[a-zA-Z]{3,}\b", full_text.lower())

    feature_names = vec.vocabulary_
    coefs = clf.coef_[0]

    contributions = []
    seen = set()
    for w in words:
        if w in feature_names and w not in seen:
            seen.add(w)
            idx = feature_names[w]
            weight = float(coefs[idx])
            contributions.append({
                "word": w,
                "weight": round(weight, 3),
                "type": "phishing" if weight > 0 else "legitimate"
            })

    contributions.sort(key=lambda x: abs(x["weight"]), reverse=True)

    # Multi-engine analysis
    result = IntelligentThreatAnalyzer.analyze(full_text, raw_phish_prob)
    result["top_words"] = contributions[:12]

    return jsonify({"status": "success", "analysis": result})


@app.route("/api/emails")
def api_emails():
    df = get_df()
    if df is None:
        return jsonify({"status": "error", "message": "Dataset not found"}), 404

    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    search = request.args.get("search", "").strip().lower()
    source = request.args.get("source", "all").lower()
    label = request.args.get("label", "all")

    filtered = df
    if source != "all":
        filtered = filtered[filtered["source"].str.lower() == source]
    if label != "all":
        filtered = filtered[filtered["label"] == int(label)]
    if search:
        filtered = filtered[filtered["text"].str.lower().str.contains(search, regex=False)]

    total = len(filtered)
    start = (page - 1) * per_page
    end = start + per_page
    sliced = filtered.iloc[start:end]

    items = []
    for idx, row in sliced.iterrows():
        items.append({
            "id": int(idx),
            "source": str(row["source"]),
            "label": int(row["label"]),
            "preview": str(row["text"])[:140] + ("..." if len(str(row["text"])) > 140 else ""),
            "full_text": str(row["text"])
        })

    return jsonify({
        "status": "success",
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": items,
        "sources": sorted(df["source"].unique().tolist())
    })


def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")


if __name__ == "__main__":
    print("=" * 60)
    print("  LAUNCHING PHISHSHIELD AI - INTELLIGENT ANALYTICS DASHBOARD")
    print("  Local Server: http://127.0.0.1:5000")
    print("=" * 60)
    Timer(1.2, open_browser).start()
    app.run(host="127.0.0.1", port=5000, debug=False)
