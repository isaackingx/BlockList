#!/usr/bin/env python3

import os
import re
import sys
import base64
import ipaddress

from bs4 import BeautifulSoup
from plyer import notification
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# ------------------------- CONFIG -------------------------
SENDER_EMAIL = "isaacblack365@gmail.com"   # <-- CHANGE to the exact sender address
SUBJECT_TEXT = "SOC Automation"            # matched as a substring; date/spacing variance ignored
LABEL_TEXT = "Malicious IPs from Core Firewall (Blocked)"
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_FILE = os.path.join(SCRIPT_DIR, "credentials.json")
TOKEN_FILE = os.path.join(SCRIPT_DIR, "token.json")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "blacklist.txt")
PROCESSED_IDS_FILE = os.path.join(SCRIPT_DIR, "processed_message_ids.txt")

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
# -------------------------------------------------------------


def get_gmail_service():
    """Authenticate and return a Gmail API service object."""
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDENTIALS_FILE):
                msg = (f"credentials.json not found in {SCRIPT_DIR}. "
                       f"See setup instructions in the script.")
                print(f"ERROR: {msg}")
                notify_failure(msg)
                sys.exit(1)
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, "w") as token_file:
            token_file.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def get_message_ids(service, sender_email, subject_text):
    """Return a list of message IDs from the given sender with a matching subject."""
    query = f'from:{sender_email} subject:"{subject_text}"'
    message_ids = []
    page_token = None

    while True:
        response = service.users().messages().list(
            userId="me", q=query, pageToken=page_token
        ).execute()
        message_ids.extend(m["id"] for m in response.get("messages", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    return message_ids


def get_message_html(service, message_id):
    """Fetch a message and return its HTML body as a string (empty if none)."""
    msg = service.users().messages().get(
        userId="me", id=message_id, format="full"
    ).execute()

    payload = msg.get("payload", {})
    return _find_html(payload)


def _find_html(payload):
    """Recursively walk the message payload looking for the text/html part."""
    mime_type = payload.get("mimeType", "")
    body_data = payload.get("body", {}).get("data")

    if mime_type == "text/html" and body_data:
        return _decode(body_data)

    for part in payload.get("parts", []) or []:
        html = _find_html(part)
        if html:
            return html

    return ""


def _decode(data):
    return base64.urlsafe_b64decode(data.encode("UTF-8")).decode("UTF-8", errors="replace")


def extract_ips_under_label(html, label_text):
    """
    Find the heading containing `label_text` followed by a count in
    parentheses (e.g. "Malicious IPs from Core Firewall (Blocked) (23)"),
    locate the HTML <table> that follows it, and pull the IP out of the
    first <td> of every row (skipping the header row).
    """
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")

    heading_pattern = re.compile(re.escape(label_text) + r"\s*\(\d+\)")
    heading_node = soup.find(string=heading_pattern)
    if not heading_node:
        return []

    table = heading_node.find_next("table")
    if not table:
        return []

    ips = []
    rows = table.find_all("tr")
    for row in rows[1:]:  # skip the header row (IP / Country / Detection / ...)
        cells = row.find_all("td")
        if not cells:
            continue
        first_cell_text = cells[0].get_text(strip=True)
        if IP_PATTERN.match(first_cell_text):
            try:
                ipaddress.ip_address(first_cell_text)
                ips.append(first_cell_text)
            except ValueError:
                continue

    return ips


def mark_as_read(service, message_id):
    """Remove the UNREAD label so the email shows as read in Gmail."""
    service.users().messages().modify(
        userId="me", id=message_id, body={"removeLabelIds": ["UNREAD"]}
    ).execute()


def load_processed_ids():
    """Return the set of message IDs already processed in previous runs."""
    if not os.path.isfile(PROCESSED_IDS_FILE):
        return set()
    with open(PROCESSED_IDS_FILE, "r") as f:
        return {line.strip() for line in f if line.strip()}


def save_processed_ids(ids_to_add):
    """Append newly processed message IDs to the tracking file."""
    with open(PROCESSED_IDS_FILE, "a") as f:
        for msg_id in ids_to_add:
            f.write(msg_id + "\n")


def notify_success(message):
    try:
        notification.notify(
            title="IP Blacklist Report: Done",
            message=message,
            app_name="IP Blacklist Automation",
            timeout=15
        )
    except Exception:
        pass  # never let a notification failure crash the script


def notify_failure(message):
    try:
        notification.notify(
            title="IP Blacklist Report: FAILED",
            message=message,
            app_name="IP Blacklist Automation",
            timeout=20
        )
    except Exception:
        pass


def sort_key(ip_str):
    try:
        return (0, ipaddress.ip_address(ip_str))
    except ValueError:
        return (1, ip_str)


def main():
    print(f"Searching for emails from: {SENDER_EMAIL}")
    print(f"Subject contains: {SUBJECT_TEXT}")
    service = get_gmail_service()

    all_message_ids = get_message_ids(service, SENDER_EMAIL, SUBJECT_TEXT)
    print(f"Found {len(all_message_ids)} total matching email(s)")

    processed_ids = load_processed_ids()
    new_message_ids = [m for m in all_message_ids if m not in processed_ids]
    print(f"Already processed previously: {len(all_message_ids) - len(new_message_ids)}")
    print(f"New email(s) to process this run: {len(new_message_ids)}")

    if not new_message_ids:
        msg = "No new report email found today. blacklist.txt was left unchanged."
        print(f"\n{msg}")
        notify_failure(msg)  # flag it so a missed daily email doesn't go unnoticed
        return

    new_ips = []
    for i, msg_id in enumerate(new_message_ids, start=1):
        html = get_message_html(service, msg_id)
        ips = extract_ips_under_label(html, LABEL_TEXT)
        print(f"  New email {i}/{len(new_message_ids)}: extracted {len(ips)} IP(s)")
        new_ips.extend(ips)
        mark_as_read(service, msg_id)

    unique_sorted_ips = sorted(set(new_ips), key=sort_key)
    print(f"\nUnique IPs in today's report: {len(unique_sorted_ips)}")

    if not unique_sorted_ips:
        msg = "Report email found, but 0 IPs were extracted. Check email format."
        print(msg)
        notify_failure(msg)
        return

    with open(OUTPUT_FILE, "w") as f:
        for ip in unique_sorted_ips:
            f.write(ip + "\n")
    print(f"Wrote results to '{OUTPUT_FILE}' (overwritten with today's list)")

    save_processed_ids(new_message_ids)
    print(f"Marked {len(new_message_ids)} email(s) as processed.")

    notify_success(f"blacklist.txt updated with {len(unique_sorted_ips)} unique IP(s).")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        print(f"\nFATAL ERROR: {error_msg}")
        notify_failure(f"Script crashed: {error_msg}")
        sys.exit(1)




















        #-----isaacking------