import os
import base64
import email
import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app import classify_email  # reuse the classifier from app.py


class GmailInbound(BaseModel):
    # Gmail push notification payload fields we care about
    message_data: str  # base64url-encoded raw email
    include_explanation: bool = True


app = FastAPI(title="Phish AI Gmail Forwarder", version="1.0.0")


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

    result = classify_email(body, headers, include_explanation=inbound.include_explanation)
    return result


@app.get("/health")
def health():
    return {"status": "ok"}
