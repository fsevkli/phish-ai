import os
import re
import difflib
import base64
import email
from pathlib import Path
from email.utils import parseaddr
from typing import Optional

import joblib
import numpy as np
import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression

try:
    import google.generativeai as genai
except ImportError:
    genai = None  # Gemini explanations will be disabled if not installed


# -----------------------------
# Configuration and artifacts
# -----------------------------
ARTIFACT_DIR = Path(os.getenv("ARTIFACT_DIR", "artifacts")).expanduser()
MODEL_PATH = Path(os.getenv("MODEL_PATH", ARTIFACT_DIR / "calibrated_model_v1.joblib"))
SENTENCE_MODEL_NAME = os.getenv(
    "SENTENCE_MODEL_NAME", "sentence-transformers/all-MiniLM-L6-v2"
)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
gemini_model = None
if genai and GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel("gemini-2.5-flash-lite")


# -----------------------------
# Feature extractor
# -----------------------------
class PhishingFeatureExtractor:
    def __init__(self):
        self.urgency_keywords = [
            "urgent",
            "immediately",
            "action required",
            "verify now",
            "suspended",
            "expired",
            "limited time",
            "act now",
            "confirm",
            "click here",
            "final notice",
            "warning",
            "alert",
            "attention",
            "important",
            "asap",
        ]
        self.cred_keywords = [
            "password",
            "login",
            "username",
            "account",
            "verify",
            "update payment",
            "billing",
            "credit card",
            "ssn",
            "social security",
            "bank",
            "paypal",
            "gift card",
            "confirm identity",
            "security question",
        ]

    def extract_all(self, text: str):
        t = text.lower()
        urg_hits = [kw for kw in self.urgency_keywords if kw in t]
        cred_hits = [kw for kw in self.cred_keywords if kw in t]
        urls = re.findall(r"https?://[^\s]+", text)
        ip_links = re.findall(r"https?://\d{1,3}(?:\.\d{1,3}){3}", text)
        long_urls = [u for u in urls if len(u) > 50]
        encoded_urls = [u for u in urls if "%" in u]
        sus_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz"]
        sus_urls = [u for u in urls for tld in sus_tlds if tld in u.lower()]
        caps_words = re.findall(r"\b[A-Z]{3,}\b", text)
        feats = {
            "urgency_count": len(urg_hits),
            "exclamations": text.count("!"),
            "caps_count": len(caps_words),
            "multi_exclam": len(re.findall(r"!{2,}", text)),
            "cred_count": len(cred_hits),
            "has_form_language": int(
                bool(re.search(r"enter your|provide your|update your|fill out", t))
            ),
            "url_count": len(urls),
            "ip_url_count": len(ip_links),
            "long_url_count": len(long_urls),
            "encoded_url_count": len(encoded_urls),
            "sus_tld_count": len(sus_urls),
        }
        details = {
            "urgency_hits": urg_hits,
            "cred_hits": cred_hits,
            "urls": urls[:3],
            "ip_links": ip_links,
            "caps_words": caps_words[:5],
        }
        return feats, details


# -----------------------------
# Header / sender analysis
# -----------------------------
def _domain_from(addr: str) -> str:
    _, email_addr = parseaddr(addr)
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower().strip()
    return ""


def _similarity(a: str, b: str) -> float:
    a = a.lower().strip()
    b = b.lower().strip()
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def analyze_headers(raw_headers: str):
    hdr_map = {}
    for line in raw_headers.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            hdr_map[k.strip()] = v.strip()

    from_hdr = hdr_map.get("From", "")
    reply_hdr = hdr_map.get("Reply-To") or hdr_map.get("Reply-to", "")
    return_hdr = hdr_map.get("Return-Path", "")
    auth_results = hdr_map.get("Authentication-Results", "")
    auth_blob = auth_results + "\n" + raw_headers

    from_domain = _domain_from(from_hdr)
    reply_domain = _domain_from(reply_hdr)
    return_domain = _domain_from(return_hdr)

    evidence = []
    risk = 0

    if reply_domain and from_domain and reply_domain != from_domain:
        risk += 1
        sim = _similarity(from_domain, reply_domain)
        evidence.append(
            f"Reply-To domain {reply_domain} differs from From {from_domain} (sim={sim:.2f})"
        )

    if return_domain and from_domain and return_domain != from_domain:
        risk += 1
        evidence.append(f"Return-Path domain {return_domain} differs from From {from_domain}")

    spf_fail = bool(
        re.search(r"spf=(fail|softfail|neutral|none|permerror|temperror)", auth_blob, re.I)
        or re.search(r"Received-SPF:\s*(fail|softfail|neutral|none|permerror|temperror)", auth_blob, re.I)
    )
    spf_pass = bool(
        re.search(r"spf=pass", auth_blob, re.I)
        or re.search(r"Received-SPF:\s*pass", auth_blob, re.I)
    )
    dmarc_fail = bool(re.search(r"dmarc=(fail|quarantine|reject)", auth_blob, re.I))
    dmarc_pass = bool(re.search(r"dmarc=pass", auth_blob, re.I))

    if spf_fail:
        risk += 1
        evidence.append("SPF failed or is neutral/none")
    if dmarc_fail:
        risk += 1
        evidence.append("DMARC failed or is in quarantine/reject")

    verdict = "low"
    if risk >= 2:
        verdict = "high"
    elif risk == 1:
        verdict = "medium"

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_domain,
        "spf_pass": spf_pass,
        "dmarc_pass": dmarc_pass,
        "risk_level": verdict,
        "risk_score": risk,
        "evidence": evidence,
        "auth_results_snippet": auth_blob[:400],
    }


# -----------------------------
# Model and encoder loading
# -----------------------------
device = "cuda" if torch.cuda.is_available() else "cpu"
sentence_model = SentenceTransformer(SENTENCE_MODEL_NAME, device=device)
feature_extractor = PhishingFeatureExtractor()

if not MODEL_PATH.exists():
    raise FileNotFoundError(f"Model not found at {MODEL_PATH}")
best_model: LogisticRegression = joblib.load(MODEL_PATH)


# -----------------------------
# Gemini explanation
# -----------------------------
def gemini_explain(email_text: str, prob_phish: float, details: dict, label: int) -> str:
    if gemini_model is None:
        return "Gemini API key not set; skipping LLM explanation."
    risk = "HIGH" if prob_phish > 0.7 else "MODERATE" if prob_phish > 0.4 else "LOW"
    risk_tags = {"HIGH": "[RED]", "MODERATE": "[YELLOW]", "LOW": "[GREEN]"}
    evidence_lines = []
    if details.get("urgency_hits"):
        evidence_lines.append(f"Urgency words: {', '.join(details['urgency_hits'][:3])}")
    if details.get("cred_hits"):
        evidence_lines.append(f"Credential/payment words: {', '.join(details['cred_hits'][:3])}")
    if details.get("urls"):
        evidence_lines.append(f"Links: {', '.join(details['urls'][:2])}")
    if details.get("ip_links"):
        evidence_lines.append("Contains IP-based link(s)")
    if details.get("caps_words"):
        evidence_lines.append(f"ALL CAPS words like {', '.join(details['caps_words'][:3])}")
    if not evidence_lines:
        evidence_lines.append("No obvious phishing indicators detected.")

    prompt = (
        "You are a cybersecurity assistant explaining phishing detections.\n\n"
        f"Email text (truncated):\n\"{email_text[:500]}\"\n\n"
        f"Model decision: {'PHISHING' if label == 1 else 'BENIGN'}\n"
        f"Model probability of phishing: {prob_phish:.2f}\n"
        f"Risk level: {risk}\n\n"
        "Evidence:\n- " + "\n- ".join(evidence_lines) + "\n\n"
        "Write 1-2 short sentences for a non-technical user:\n"
        f"1) Start with the exact token {risk_tags[risk]} (no emoji).\n"
        "2) Briefly explain why (urgency, credential asks, suspicious links).\n"
        "3) Give one clear recommended action.\n\n"
        "Stay under 80 words. Avoid any emoji; use plain ASCII."
    )
    try:
        resp = gemini_model.generate_content(prompt)
        text = resp.text.strip()
        emoji_map = {
            "🟥": "[RED]",
            "🔴": "[RED]",
            "🟧": "[YELLOW]",
            "🟨": "[YELLOW]",
            "🟡": "[YELLOW]",
            "🟩": "[GREEN]",
            "🟢": "[GREEN]",
        }
        for emo, tag in emoji_map.items():
            text = text.replace(emo, tag)
        if not any(text.startswith(tag) for tag in risk_tags.values()):
            text = f"{risk_tags[risk]} {text}"
        return text
    except Exception as exc:  # pragma: no cover - depends on external service
        return f"Could not generate explanation: {exc}"


# -----------------------------
# Inference
# -----------------------------
def classify_email(email_text: str, raw_headers: str = "", include_explanation: bool = True):
    f_vec, details = feature_extractor.extract_all(email_text)
    f_arr = np.array(list(f_vec.values()), dtype=float).reshape(1, -1)
    emb_vec = sentence_model.encode([email_text])
    x_hybrid = np.hstack([f_arr, emb_vec])

    prob_phish = best_model.predict_proba(x_hybrid)[0, 1]
    label = int(prob_phish >= 0.5)
    risk = "HIGH" if prob_phish > 0.7 else "MODERATE" if prob_phish > 0.4 else "LOW"

    hdr = analyze_headers(raw_headers or "")
    combined_prob = min(1.0, prob_phish + 0.08 * hdr["risk_score"])
    combined_label = "phishing" if combined_prob >= 0.5 else "benign"
    explanation = (
        gemini_explain(email_text, prob_phish, details, label) if include_explanation else ""
    )

    return {
        "label": "phishing" if label == 1 else "benign",
        "prob_phish": prob_phish,
        "risk": risk,
        "details": details,
        "header_analysis": hdr,
        "combined_prob_phish": combined_prob,
        "combined_label": combined_label,
        "explanation": explanation,
    }


# -----------------------------
# API definition
# -----------------------------
class ClassifyRequest(BaseModel):
    email_text: str
    raw_headers: Optional[str] = ""
    include_explanation: bool = True


class GmailInbound(BaseModel):
    # Expect base64url-encoded raw email (e.g., from a Gmail webhook/Apps Script)
    message_data: str
    include_explanation: bool = True


app = FastAPI(title="Phish AI", version="1.0.0")


@app.get("/health")
def health():
    return {"status": "ok", "model_path": str(MODEL_PATH), "device": sentence_model.device}


@app.post("/classify")
def classify(req: ClassifyRequest):
    return classify_email(
        email_text=req.email_text,
        raw_headers=req.raw_headers or "",
        include_explanation=req.include_explanation,
    )


def parse_raw_email(encoded: str):
    try:
        raw_bytes = base64.urlsafe_b64decode(encoded.encode("utf-8"))
        msg = email.message_from_bytes(raw_bytes)
    except Exception as exc:
        raise ValueError(f"Could not decode email: {exc}")

    raw_headers = ""
    for k, v in msg.items():
        raw_headers += f"{k}: {v}\n"

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if ctype == "text/plain" and "attachment" not in disp:
                body = part.get_payload(decode=True).decode(errors="ignore")
                break
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    return body, raw_headers


@app.post("/gmail-hook")
def gmail_hook(inbound: GmailInbound):
    try:
        body, headers = parse_raw_email(inbound.message_data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return classify_email(
        email_text=body,
        raw_headers=headers,
        include_explanation=inbound.include_explanation,
    )


@app.get("/")
def root():
    return {
        "message": "Phish AI API. Use POST /classify with email_text/raw_headers or POST /gmail-hook with base64url raw email."
    }
