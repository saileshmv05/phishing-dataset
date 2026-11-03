# PhishShield AI — Intelligent Phishing Detection & ML Analytics Dashboard

An end-to-end multi-factor machine learning and semantic intent analysis system for detecting phishing and spam emails across diverse datasets, featuring an executive dark-mode web dashboard inspired by modern fintech/logistics analytics, an intelligent context-aware mitigation engine, and a complete academic report.

---

## Quick Launch (.bat files)

- **[run_dashboard.bat](file:///d:/phishing-detection/run_dashboard.bat)**: **(Recommended)** Launches the dark-mode web analytics dashboard at `http://127.0.0.1:5000` and automatically opens your default browser.
- **[run_gui.bat](file:///d:/phishing-detection/run_gui.bat)**: Launches the local desktop Tkinter GUI application.
- **[run.bat](file:///d:/phishing-detection/run.bat)**: Interactive terminal menu providing options to launch the web dashboard, desktop GUI, retrain models, rebuild datasets, or explore raw data.

---

## Project Highlights

1. **Modern Dark Dashboard (Tailwind CSS + Chart.js)**
   - Styled with dark obsidian backgrounds, glowing amber/orange accents (`#ff6e30`), and emerald green status badges.
   - Live interactive decision threshold area chart, 2x2 confusion matrix cards, stacked dataset distribution, and metrics comparison bar charts.
   - Real-time Intelligent Threat Scanner with animated confidence meter and token-level Explainable AI (XAI) keyword badges.
   - Interactive Decision Threshold simulator with live-updating sliders.
   - Searchable database of all 158,088 deduplicated emails with full-text inspection modal.

2. **Multi-Factor Intelligent Threat Engine**
   - Solves the string-matching "keyword fallacy" where clean business or university emails with words like *"bank"*, *"account"*, or *"invoice"* get falsely flagged.
   - Evaluates 4 pillars: Lexical TF-IDF ML + Psychological Urgency + Link/Domain Anomalies + Safe Context Mitigation.

3. **Academic Deliverables**
   - **[PROJECT_REPORT.md](file:///d:/phishing-detection/PROJECT_REPORT.md)**: Full academic thesis/report document with mathematical formulations, empirical evaluations, literature review, and false-alarm mitigation case studies.
