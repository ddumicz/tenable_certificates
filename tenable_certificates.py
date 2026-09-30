#!/usr/bin/env python3

import csv
import os
import re
import requests
import urllib3

# ============================================================
# CONFIGURATION
# ============================================================

TENABLE_SC_URL = os.getenv("TENABLE_SC_URL", "https://tenable-sc.example.com")
ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY")
SECRET_KEY = os.getenv("TENABLE_SECRET_KEY")

OUTPUT_FILE = "tenable_certificates.csv"

# W środowisku produkcyjnym najlepiej pozostawić True.
VERIFY_SSL = True

PLUGIN_ID = "10863"
PAGE_SIZE = 1000


# ============================================================
# TENABLE.SC API
# ============================================================

def get_headers():
    if not ACCESS_KEY or not SECRET_KEY:
        raise RuntimeError(
            "Ustaw zmienne TENABLE_ACCESS_KEY i TENABLE_SECRET_KEY"
        )

    return {
        "x-apikey": f"accesskey={ACCESS_KEY}; secretkey={SECRET_KEY};",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def fetch_certificates():
    results = []
    start = 0

    while True:
        payload = {
            "type": "vuln",
            "sourceType": "cumulative",
            "query": {
                "type": "vuln",
                "tool": "vulndetails",
                "filters": [
                    {
                        "filterName": "pluginID",
                        "operator": "=",
                        "value": PLUGIN_ID,
                    }
                ],
                "startOffset": start,
                "endOffset": start + PAGE_SIZE,
            },
        }

        response = requests.post(
            f"{TENABLE_SC_URL}/rest/analysis",
            headers=get_headers(),
            json=payload,
            verify=VERIFY_SSL,
            timeout=120,
        )

        response.raise_for_status()

        data = response.json()

        if data.get("error_code", 0) != 0:
            raise RuntimeError(
                f"Tenable.sc error: {data.get('error_msg')}"
            )

        page = data.get("response", {}).get("results", [])

        if not page:
            break

        results.extend(page)

        print(
            f"Pobrano {len(page)} rekordów "
            f"(łącznie {len(results)})"
        )

        if len(page) < PAGE_SIZE:
            break

        start += PAGE_SIZE

    return results


# ============================================================
# PARSING CERTIFICATE
# ============================================================

def extract(patterns, text):
    for pattern in patterns:
        match = re.search(
            pattern,
            text,
            re.MULTILINE | re.IGNORECASE,
        )

        if match:
            return match.group(1).strip()

    return ""


def parse_certificate(result):
    text = (
        result.get("pluginText")
        or result.get("pluginOutput")
        or ""
    )

    subject_cn = extract([
        r"Subject.*?Common Name\s*[:=]\s*(.+)",
        r"Subject.*?CN\s*=\s*([^,\n/]+)",
        r"Subject\s*:\s*.*?CN\s*=\s*([^,\n/]+)",
    ], text)

    issuer_cn = extract([
        r"Issuer.*?Common Name\s*[:=]\s*(.+)",
        r"Issuer.*?CN\s*=\s*([^,\n/]+)",
    ], text)

    issuer_org = extract([
        r"Issuer.*?Organization\s*[:=]\s*(.+)",
        r"Issuer.*?O\s*=\s*([^,\n/]+)",
    ], text)

    serial = extract([
        r"Serial(?: Number)?\s*[:=]\s*(.+)",
    ], text)

    valid_from = extract([
        r"Not Before\s*[:=]\s*(.+)",
        r"Valid From\s*[:=]\s*(.+)",
    ], text)

    valid_to = extract([
        r"Not After\s*[:=]\s*(.+)",
        r"Valid (?:To|Until)\s*[:=]\s*(.+)",
    ], text)

    san = extract([
        r"Subject Alternative Name[s]?\s*[:=]\s*(.+)",
    ], text)

    return {
        "IP": result.get("ip", ""),
        "DNS": result.get("dnsName", ""),
        "Port": result.get("port", ""),
        "Protocol": result.get("protocol", ""),
        "CN": subject_cn,
        "SAN": san,
        "Issuer CN": issuer_cn,
        "Issuer Organization": issuer_org,
        "Serial Number": serial,
        "Valid From": valid_from,
        "Valid To": valid_to,
        "Last Seen": result.get("lastSeen", ""),
        "Repository": (
            result.get("repository", {}).get("name", "")
            if isinstance(result.get("repository"), dict)
            else result.get("repository", "")
        ),
        "Plugin Output": text,
    }


# ============================================================
# CSV
# ============================================================

def save_csv(certificates):
    fields = [
        "IP",
        "DNS",
        "Port",
        "Protocol",
        "CN",
        "SAN",
        "Issuer CN",
        "Issuer Organization",
        "Serial Number",
        "Valid From",
        "Valid To",
        "Last Seen",
        "Repository",
        "Plugin Output",
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields,
            delimiter=";",
        )

        writer.writeheader()
        writer.writerows(certificates)


# ============================================================
# MAIN
# ============================================================

def main():
    if not VERIFY_SSL:
        urllib3.disable_warnings(
            urllib3.exceptions.InsecureRequestWarning
        )

    print("Pobieranie danych z Tenable Security Center...")

    findings = fetch_certificates()

    print(f"Plugin {PLUGIN_ID}: {len(findings)} wyników")

    certificates = [
        parse_certificate(result)
        for result in findings
    ]

    save_csv(certificates)

    print(
        f"Gotowe: {len(certificates)} certyfikatów "
        f"zapisano do {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
