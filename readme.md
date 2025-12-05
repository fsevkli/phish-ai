Project Overview
----------------
- Goal: Hybrid phishing email detection that combines engineered security features with MiniLM embeddings, calibrated logistic regression, and Gemini-generated explanations. Designed for repeatable Colab runs with cached artifacts.
- Why: Phishing is the top entry point for compromise. Analysts and users need calibrated probabilities, evidence, and plain-language reasons rather than opaque flags.
- Scope: Detection accuracy, interpretability, and basic robustness testing across two public datasets (HF + Kaggle) plus adversarial low-signal phish.

Data
----
- Primary: Hugging Face `zefang-liu/phishing-email-dataset` (cleaned to `email` + binary `label`).
- Secondary (robustness): Kaggle `subhajournal/phishingemails`, aligned to the same schema.
- Splits: Stratified 70/15/15 train/val/test on the HF set. Split indices are cached so reruns reuse the same split.

Features and Model
------------------
- Engineered indicators (11): urgency/credential keyword counts, exclamation bursts, ALL-CAPS words, form-language flag, URL counts (long/encoded/IP/suspicious TLD).
- Embeddings: `sentence-transformers/all-MiniLM-L6-v2` (GPU if available).
- Hybrid representation: concatenated features + embeddings.
- Classifier: Logistic Regression with Platt calibration (`CalibratedClassifierCV`). Metrics reported on HF test; robustness metrics on Kaggle.
- Explanations: Gemini-based short rationales driven by feature hits; falls back to a static string if `GEMINI_API_KEY` is not set.

Operational Additions
---------------------
- Caching: cleaned datasets, split indices, embeddings, and the calibrated model are saved to `ARTIFACT_DIR` (default `/content/drive/MyDrive/phishing_ai` on Colab). Reruns load artifacts and skip retraining/encoding.
- FAISS (optional): build/load a MiniLM index for nearest-neighbor lookups to surface similar training emails in explanations. Saves `minilm.index` + id map to `ARTIFACT_DIR`.
- Header analysis: helper to score Reply-To/Return-Path mismatches and SPF/DMARC results, blending header risk into the probability.
- Adversarial checks: curated low-signal, grammatically clean phishing prompts to spot regression on subtle attacks.

Colab Run Order (suggested)
---------------------------
1) Mount Drive: `from google.colab import drive; drive.mount('/content/drive')` and set `ARTIFACT_DIR` if you want a custom path.
2) Set key: `%env GEMINI_API_KEY=...` (optional for LLM explanations).
3) Run the main pipeline cell (first code cell): downloads/cleans data if not cached, reuses cached splits/embeddings/model if present, trains/calibrates otherwise, and prints metrics.
4) (Optional) Run FAISS cell to build/load the index and persist it to Drive.
5) Use `classify_email_with_headers(email_text, raw_headers)` for forwarded Gmail/Outlook samples (paste full raw headers from “Show original”).
6) Run the adversarial test cell to sanity-check low-signal phish handling.

Next Steps
----------
1) Deployment: wire a simple API or Gmail forwarding handler that calls `classify_email_with_headers`, logs decisions, and stores samples for continual learning.
2) Header depth: add domain similarity via Levenshtein/tokenized subdomain checks; optionally parse ARC/Received chains for hop anomalies.
3) Safety/LLM: tighten Gemini prompt templates and add length guards; consider local explanation fallback (template-based) for offline use.

API (no notebook)
-----------------
- Files: `app.py`, `requirements.txt`. Point `ARTIFACT_DIR` (env) at the directory holding `calibrated_model_v1.joblib` and the MiniLM encoder downloads (HF will fetch on first run).
- Run locally:
  - `pip install -r requirements.txt`
  - `export GEMINI_API_KEY=...` (optional)
  - `uvicorn app:app --host 0.0.0.0 --port 8000`
- Endpoints:
  - `POST /classify` with JSON `{"email_text": "...", "raw_headers": "...", "include_explanation": true}`. Returns label, probabilities, header analysis, and Gemini explanation if configured.
  - `POST /gmail-hook` with JSON `{"message_data": "<base64url raw email>", "include_explanation": true}`. Use this for Gmail forwards/webhooks (supply the raw email in base64url). 
  - `GET /health` for a quick check.
