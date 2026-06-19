"""
Exchange Security Alert Monitor
Logs in via OWA (Outlook Web Access) form-based authentication,
then uses the Exchange REST API to search for security alert emails.
Sends a notification if "attack detected but not blocked" is found.
Credentials are stored in Windows Credential Manager (never plain text).
"""

import sys
import json
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta

import requests
from requests_ntlm import HttpNtlmAuth
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_FILE    = os.path.join(os.path.dirname(__file__), "exchange_alert_config.json")
PROCESSED_FILE = os.path.join(os.path.dirname(__file__), "exchange_alert_processed.json")
SERVICE_NAME   = "ExchangeSecurityAlertMonitor"

SEARCH_SUBJECT = "Security Alert by Number of Attacked Computers"
SEARCH_STRING  = "attack detected but not blocked"


# ── Config & credentials ──────────────────────────────────────────────────────

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"ERROR: Config file not found: {CONFIG_FILE}")
        sys.exit(1)
    with open(CONFIG_FILE) as f:
        return json.load(f)


def load_credentials():
    try:
        import keyring
    except ImportError:
        print("ERROR: keyring not installed. Run: pip install keyring")
        sys.exit(1)

    username = keyring.get_password(SERVICE_NAME, "username")
    password = keyring.get_password(SERVICE_NAME, "password")

    if not username or not password:
        print(f"ERROR: No credentials found in Windows Credential Manager for '{SERVICE_NAME}'.")
        print("Run exchange_alert_setup.py first.")
        sys.exit(1)

    return username, password


# ── Processed email tracking ─────────────────────────────────────────────────

def load_processed():
    if os.path.exists(PROCESSED_FILE):
        with open(PROCESSED_FILE) as f:
            return set(json.load(f))
    return set()


def save_processed(ids):
    with open(PROCESSED_FILE, "w") as f:
        json.dump(list(ids), f)


# ── OWA login ────────────────────────────────────────────────────────────────

def owa_login(server, username, password):
    """
    Performs OWA form-based authentication.
    Returns an authenticated requests.Session on success.
    """
    session = requests.Session()
    session.verify = False  # accept self-signed certs common in on-prem Exchange

    base_url  = f"https://{server}"
    auth_url  = f"{base_url}/owa/auth.owa"
    dest_url  = f"{base_url}/owa/"

    # Some Exchange versions use /owa/auth/owaauth.dll — try both
    payload = {
        "destination": dest_url,
        "flags":       "4",
        "username":    username,
        "password":    password,
        "isUtf8":      "1",
    }

    resp = session.post(auth_url, data=payload, allow_redirects=True, timeout=30)

    # Detect login failure: OWA redirects to /owa/ on success;
    # a failed login stays on the auth page or returns 440/403.
    if resp.status_code in (440, 403):
        print(f"ERROR: OWA login failed (HTTP {resp.status_code}). Check credentials.")
        sys.exit(1)

    if "reason=0" in resp.url or "logon" in resp.url.lower():
        print("ERROR: OWA login failed — redirected back to login page. Check credentials.")
        sys.exit(1)

    print(f"OWA login successful ({resp.url})")
    return session


# ── Email search via Exchange REST API ───────────────────────────────────────

def fetch_messages(session, server, since_iso, username, password):
    """
    Searches the inbox using the Exchange REST API (/api/v2.0/).
    The REST API requires its own Basic auth — OWA session cookie alone is not accepted.
    Returns a list of message dicts.
    """
    url = f"https://{server}/api/v2.0/me/MailFolders/Inbox/Messages"

    params = {
        "$filter":  f"ReceivedDateTime ge {since_iso}",
        "$select":  "Id,Subject,From,ReceivedDateTime,Body,UniqueBody",
        "$top":     50,
        "$orderby": "ReceivedDateTime desc",
    }

    headers = {
        "Accept":       "application/json",
        "Content-Type": "application/json",
    }

    resp = session.get(url, params=params, headers=headers,
                       auth=HttpNtlmAuth(username, password), timeout=30)

    if resp.status_code == 404:
        print("ERROR: Exchange REST API not found (/api/v2.0/). "
              "Your server may be Exchange 2013 or older — contact your admin.")
        sys.exit(1)

    if not resp.ok:
        print(f"ERROR: Failed to fetch messages (HTTP {resp.status_code}): {resp.text[:300]}")
        sys.exit(1)

    return resp.json().get("value", [])


# ── Alert email ───────────────────────────────────────────────────────────────

def send_alert(config, username, password, original_subject, sender, received_time, excerpt):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "ACTION REQUIRED: Unblocked Attack Detected in Security Alert"
    msg["From"]    = config["mailbox"]
    msg["To"]      = config["alert_to"]

    body = f"""An email matching the monitored security criteria was detected.

---
ORIGINAL EMAIL DETAILS
Subject  : {original_subject}
From     : {sender}
Received : {received_time}

MATCHED CONTENT (excerpt)
{excerpt}

---
ACTION REQUIRED: Please review the security alert immediately.

This notification was generated automatically by the Exchange Security Alert Monitor.
"""
    msg.attach(MIMEText(body, "plain"))

    smtp_server = config.get("smtp_server", config["exchange_server"])
    smtp_port   = config.get("smtp_port", 587)

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.ehlo()
        if smtp_port != 25:
            server.starttls()
        server.login(username, password)
        server.sendmail(config["mailbox"], config["alert_to"], msg.as_string())

    print(f"Alert email sent to {config['alert_to']}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    config              = load_config()
    username, password  = load_credentials()
    processed           = load_processed()

    exchange_server = config["exchange_server"]

    # OWA login
    session = owa_login(exchange_server, username, password)

    # Fetch emails from the last 24 hours
    since     = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    messages = fetch_messages(session, exchange_server, since_iso, username, password)

    found         = False
    new_processed = set(processed)

    for msg in messages:
        # Filter by subject
        subject = msg.get("Subject", "")
        if SEARCH_SUBJECT.lower() not in subject.lower():
            continue

        item_id = msg.get("Id", "")
        if item_id in processed:
            continue

        # Extract body text
        body_obj  = msg.get("UniqueBody") or msg.get("Body") or {}
        body_text = body_obj.get("Content", "") if isinstance(body_obj, dict) else ""

        if SEARCH_STRING.lower() in body_text.lower():
            idx    = body_text.lower().find(SEARCH_STRING.lower())
            start  = max(0, idx - 100)
            end    = min(len(body_text), idx + len(SEARCH_STRING) + 200)
            excerpt = body_text[start:end].strip()

            sender_obj   = msg.get("From", {}).get("EmailAddress", {})
            sender_str   = f"{sender_obj.get('Name', '')} <{sender_obj.get('Address', '')}>"
            received_str = msg.get("ReceivedDateTime", "")

            print(f"Match found: '{subject}' from {sender_str} at {received_str}")
            send_alert(
                config, username, password,
                original_subject=subject,
                sender=sender_str,
                received_time=received_str,
                excerpt=excerpt,
            )
            new_processed.add(item_id)
            found = True

    save_processed(new_processed)

    if not found:
        print("No new matching emails found.")


if __name__ == "__main__":
    main()
