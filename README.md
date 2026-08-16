# BlockList
An automation script that reads my email, compile and sort malicious IPs for daily blocking on the firewall

# BlockList: Automated Threat Intel Email Harvester

A lightweight automation tool designed to bridge the gap between email-based threat intelligence and active firewall enforcement. This script automatically parses security alerts, extracts malicious IPs, consolidates them, and feeds them into firewalls to block active threats daily.

 Key Features
*   **Automated IMAP Extraction:** Connects securely over SSL to harvest threat data without human intervention.
*   **Data Sanitization & De-duplication:** Filters out internal networks, RFC 1918 addresses, and duplicates using strict regex validation.
*   **Firewall-Ready Output:** Generates a standardized threat feed format compatible with external dynamic lists (EDL).
*   **Secure Credential Management:** Utilizes environment variables (`.env`) to protect API keys and mail passwords.

 Architecture
[Email Alert] ➔ [IMAP/API Script Fetch] ➔ [Regex Parsing & Sanitization] ➔ [Unified Threat Feed] ➔ [Firewall Block List]

 Tech Stack
*   **Language:** Python 3.x
*   **Libraries:** `re` (Regex), `imaplib` / `imapclient`, `python-dotenv`
*   **Target Integration:** [Insert your Firewall, e.g., pfSense EDL / Fortinet Network Group] (Though I manuallly implement that due to strict comppany policy) but you can upgrade it to your taste

 Installation & Setup
1. Clone the repository...
2. Configure your `.env` file...
3. Set up a daily cron job...

