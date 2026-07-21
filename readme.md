# 🪲 SandBoxEQ

A multi-API threat intelligence scanner for hashes across popular free threat intelligence APIs, including VirusTotal, AlienVault OTX, MalwareBazaar, ThreatFox, and Hybrid Analysis.

---

## Features

- Query MD5, SHA1, and SHA256 file hashes against multiple threat intelligence sources concurrently.
- Auto-rescan stale VirusTotal reports older than 30 days.
- Displays digital certificate information (publisher, issuer, validity) from VirusTotal.
- Color-coded output for clear threat status.
- Web interface built with FastAPI for easy access and usability.
- Clickable links to detailed reports from API providers.

---

## Installation

### Prerequisites

- Python 3.7+
- Internet connection
- API keys for supported threat intelligence services:
  - VirusTotal
  - AlienVault OTX
  - MalwareBazaar
  - ThreatFox
  - Hybrid Analysis

### Setup

1. Clone or download this repository.

2. Create a `config.env` file in the project root with the following variables:

VT_API_KEY=your_virustotal_api_key_here
OTX_API_KEY=your_otx_api_key_here
MB_API_KEY=your_malwarebazaar_api_key_here
THREATFOX_API_KEY=your_threatfox_api_key_here
HYBRID_API_KEY=your_hybrid_analysis_api_key_here

and run

`pip install -r requirements.txt`

### How to get API Keys

1. VirusTotal API Key
   Website: https://www.virustotal.com/

Steps to get API key:

Create a free account at VirusTotal.

After logging in, navigate to your profile by clicking your user icon.

Click on API Key or API section.

Copy your personal API key (usually a long alphanumeric string).

Paste this key into your project's config.env file as VT_API_KEY=your_api_key.

Notes:

Free tier has request limits (public API key usage limits on requests per minute/day).

For higher limits or advanced features, paid subscription required.

2. AlienVault OTX (Open Threat Exchange) API Key
   Website: https://otx.alienvault.com/

Steps to get API key:

Sign up for a free account with AlienVault OTX.

Log in and go to the User Settings or Profile menu.

Find the API Key section.

Copy the API key shown.

Add it to your config.env file as OTX_API_KEY=your_api_key.

Notes:

OTX is community-powered and free to use with API limits.

3. MalwareBazaar API Key
   Website: https://bazaar.abuse.ch/api/

Steps to get API key:

Create an account on MalwareBazaar via abuse.ch.

Log in and navigate to your account settings/profile.

Find the API key generation area.

Generate or copy your existing API key.

Set it in your config.env as MB_API_KEY=your_api_key.

Notes:

API key required for authenticated requests.

Free access often limited for registered users.

4. ThreatFox API Key
   Website: https://threatfox.abuse.ch/

Steps to get API key:

Register for an account on ThreatFox.

Log in, then visit your profile or API settings.

Retrieve the API key from the dashboard.

Add it to config.env as THREATFOX_API_KEY=your_api_key.

Notes:

ThreatFox API enables searching for hashes and other IoCs.

Watch for API usage policies.

5. Hybrid Analysis API Key
   Website: https://www.hybrid-analysis.com/

Steps to get API key:

Sign up for a free user account on Hybrid Analysis.

After email verification, log in to your dashboard.

Find and copy your API key or API token under your user profile or API section.

Store the key in config.env like HYBRID_API_KEY=your_api_key.

Notes:

Hybrid Analysis free tier has rate limits on API usage.

Consider paid plans for larger usage.

General Advice for All API Keys
Store all API keys securely in your local .env or config.env file.

Do NOT commit API keys to public source control repositories.

Follow each provider's documentation about rate limits and usage policies.

Rotate keys if compromised or shared accidentally.

python -m PyInstaller --onefile --add-data "templates;templates" --add-data "static;static" --add-data "config.env;." --hidden-import=uvicorn --hidden-import=fastapi --hidden-import=dotenv --name MyFastAPIApp launch_app.py


