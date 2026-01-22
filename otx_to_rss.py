import os
import requests
from datetime import datetime, timezone
from feedgen.feed import FeedGenerator

# ================= OTX CONFIG =================
OTX_API_KEY ="9e745d53bceda7f1846683fe32dde02a9952ac07a1333518c7a1ad879f3a1508"

if not OTX_API_KEY:
    print("OTX_API_KEY environment variable not set")
    exit(1)

OTX_URL = "https://otx.alienvault.com/api/v1/pulses/activity"

headers = {
    "X-OTX-API-KEY": OTX_API_KEY,
    "User-Agent": "ThreatIntelFeed/1.0"
}

# ==============================
# FETCH DATA FROM OTX
# ==============================
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

print("[*] Fetching AlienVault OTX...")

session = requests.Session()

retries = Retry(
    total=3,
    backoff_factor=5,          # 5s, 10s, 20s
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"]
)

session.mount("https://", HTTPAdapter(max_retries=retries))

try:
    resp = session.get(
        OTX_URL,
        headers=headers,
        timeout=(10, 60)   # 10s connect, 60s read
    )

    if resp.status_code != 200:
        print(f"[!] OTX HTTP {resp.status_code}")
        print(resp.text[:200])
        pulses = []
    else:
        pulses = resp.json().get("results", [])
        print(f"[✔] OTX pulses fetched: {len(pulses)}")

except requests.exceptions.ReadTimeout:
    print("[!] OTX read timeout — skipping this run")
    pulses = []

except requests.exceptions.RequestException as e:
    print(f"[!] OTX request failed: {e}")
    pulses = []


# ==============================
# CREATE RSS FEED
# ==============================
fg = FeedGenerator()
fg.title("AlienVault OTX – Latest IOC Pulses")
fg.link(href="https://otx.alienvault.com", rel="alternate")
fg.description("Latest threat intelligence pulses and IOCs from AlienVault OTX")
fg.language("en")


#===============================
# Maximum IOCs
#===============================
MAX_PULSES = 10
MAX_IOCS_PER_PULSE = 10

for pulse in pulses[:MAX_PULSES]:
    indicators = pulse.get("indicators", [])

    for ind in indicators[:MAX_IOCS_PER_PULSE]:
        ioc_type = ind.get("type")
        ioc_value = ind.get("indicator")

        if not ioc_value:
            continue

# ==============================
# BUILD RSS ENTRIES
# ==============================
for pulse in pulses:
    entry = fg.add_entry()

    pulse_id = pulse.get("id")
    pulse_name = pulse.get("name", "OTX Pulse")
    created = pulse.get("created")

    entry.title(pulse_name)
    entry.link(href=f"https://otx.alienvault.com/pulse/{pulse_id}")

    if created:
        created_dt = datetime.fromisoformat(
            created.replace("Z", "")
        ).replace(tzinfo=timezone.utc)
    else:
        created_dt = datetime.now(timezone.utc)

    entry.published(created_dt)

    ioc_lines = []
    for ind in pulse.get("indicators", [])[:MAX_IOCS_PER_PULSE]:
        ioc_lines.append(f"{ind.get('type')}: {ind.get('indicator')}")

    description = f"""
<b>Author:</b> {pulse.get('author_name', 'Unknown')}<br/>
<b>Tags:</b> {', '.join(pulse.get('tags', []))}<br/><br/>
<b>IOCs:</b><br/>
<pre>{chr(10).join(ioc_lines)}</pre>
"""

    entry.description(description)


# ==============================
# WRITE RSS FILE
# ==============================
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
FEEDS_DIR = BASE_DIR / "feeds"
FEEDS_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = FEEDS_DIR / "threat_intel.xml"

