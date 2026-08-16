# 🪲 SandBoxEQ

**Enhanced Multi-API Threat Intelligence Scanner** — a single tool for a security team to answer two questions fast:

1. **Is this file hash/downloaded application malicious?** — fan a hash out across 7 free sandboxes/threat-intel APIs at once, or upload a file for real sandbox detonation.
2. **Is this URL safe?** — fan a URL out across 10 free reputation/category APIs, check its TLS certificate, Certificate Transparency history, domain age, redirect behavior, and brand-lookalike risk, and get a composite **Whitelist / Caution / Block** recommendation — built for two concrete workflows:
   - **Enterprise URL whitelisting** — deciding whether a site should be allowed for the workforce.
   - **Download-source validation** — checking whether the site an application was downloaded from is legitimate, cross-checking the download URL against the file's own hash either way round (via **Advanced Options** on the Single Lookup tab).

Everything runs locally against your own API keys — no file contents or URLs are sent anywhere except the threat-intel providers you've configured, and only when you run a lookup.

---

## What it can do

| Tab | What it's for |
|---|---|
| **Single Lookup** | Paste a hash *or* a URL into one box — auto-detected and routed to the right engine. An **Advanced Options** panel lets you additionally give the hash of a downloaded file *and/or* the URL it came from, for download-source-validation cross-checking regardless of which one you put in the main box. |
| **Digital Certificate** | Drop a Windows executable (`.exe`/`.dll`/`.sys`/`.msi`) to inspect its Authenticode signature — publisher, issuing CA, validity, tamper status. Parsed **entirely in your browser**; the file is never uploaded. |
| **Bulk Analysis** | Upload a CSV of hashes and/or URLs (column named `hash`, `url`, `indicator`, `value`, or `ioc`) for batch scanning, with a downloadable CSV of results. |
| **Sandbox Upload** | Upload a real file to VirusTotal, MetaDefender, Hybrid Analysis, and/or Triage for full sandbox detonation, with live progress. |
| **Settings** | Enter/update API keys, split into a **Hash/File Scanning APIs** sub-tab and a **URL Scanning APIs** sub-tab. Keys are stored locally in `config.env`; blank fields keep whatever's already saved. |
| **Terminal** | Live, plain-text log of every provider call as a scan runs. |
| **History & Bookmarks** | Recent searches and saved lookups, with one-click re-scan. |

### Hash lookups check
VirusTotal, MetaDefender, AlienVault OTX, MalwareBazaar, ThreatFox, Hybrid Analysis, and Triage Sandbox — concurrently, with a weighted 0–100 threat score. VirusTotal reports auto-rescan if older than 30 days, and code-signing/timestamp certificate details are shown when available.

### URL lookups check
- **Reputation/verdict**: VirusTotal, MetaDefender, AlienVault OTX, URLhaus, Hybrid Analysis (quick scan), OpenPhish, IPQualityScore, urlscan.io (with a live screenshot), and CheckPhish. (Triage and Google Safe Browsing are deliberately **not** included here — see the notes in the API key table below.)
- **Category**: merged from whichever of VirusTotal / MetaDefender / IPQualityScore reported one — the practical substitute for an authoritative Palo Alto PAN-DB / Symantec WebPulse category, neither of which exposes a public API (only queryable live through an appliance you own).
- **Certificate legitimacy**: an always-on, keyless TLS handshake check (expiry, trust chain, issuer, certificate age) plus a keyless Certificate Transparency history lookup (SSLMate Certspotter, falling back to crt.sh). An optional on-demand Qualys SSL Labs deep-dive grade is available per URL.
- **Domain age**: free, keyless RDAP lookup — a domain registered days ago is a meaningful risk signal on its own.
- **Redirect chain**: follows redirects hop by hop and flags when a URL lands on a different domain than it started on.
- **Brand lookalike / typosquat check**: instant, offline comparison against a small built-in list of commonly-impersonated brand domains (Microsoft, Google, PayPal, banks, ...) — flags near-misses like `microsft.com`.
- **Favicon match**: fetches the site's favicon and, when the typosquat check already flagged a close brand match, fetches that brand's real favicon too and compares hashes — an exact match on a domain that ISN'T the real brand is hard evidence of a cloned phishing kit, not just a similar-looking name.
- **IDN / homoglyph check**: flags internationalized domains that mix in a script commonly used to spoof Latin lookalikes (Cyrillic "а" vs Latin "a", etc.) — catches the class of attack that slips right past the plain-ASCII typosquat check above.
- **URL structure check**: instant, offline red flags — raw IP address as the host, an `@` before the host (classic destination-disguising trick), unusually deep subdomain nesting, disproportionately-abused TLDs (`.tk`, `.top`, `.xyz`, ...), known URL-shorteners, and unusually long URLs.
- **Download Content-Type check**: for a URL that looks like a direct file download, a HEAD request confirms the server actually serves that file type — an `.exe` URL serving back HTML is very often a dead link or gate page, not the real installer.
- **Hosting reputation (AbuseIPDB)**: resolves the domain's IP and checks it against AbuseIPDB's abuse-report history — infrastructure-level reputation that's independent of anything about the domain name itself.
- **Composite verdict**: category + risk score + certificate status + all of the signals above, rolled into one Whitelist / Caution — Manual Review / Block banner.
- **Download cross-check**: give the hash of a downloaded file *and/or* the URL it came from (Advanced Options, Single Lookup tab) and VirusTotal's "files seen downloaded from this URL" relationship is checked between them — works starting from either the hash or the URL.

Every provider is optional — the app only queries whichever keys you've configured, and continues normally (with a "not configured" skip, or a per-provider error card) around the ones you haven't.

---

## Installation

### Prerequisites

- Python 3.7+
- Internet connection
- API keys for whichever providers you want (see below) — **none are required to run the app**, but the more you configure, the more complete each result is.

### Setup

1. Clone or download this repository.
2. Install dependencies:

   ```
   pip install -r requrements.txt
   ```

3. Run the app:

   ```
   python launch_app.py
   ```

   then open **http://127.0.0.1:8000/**.

4. Open the **Settings** tab in the app and paste in whichever API keys you have — this writes them to a local `config.env` next to the app (created automatically on first run). You can also create/edit `config.env` by hand instead, with `KEY=value` lines matching the table below.

---

## How to get API keys

All of these have a free tier. Store keys only in `config.env` (already git-ignored) — never commit them to source control, and rotate a key immediately if it's ever exposed.

### Hash/file-scanning APIs

| Provider | `config.env` variable | Get a key at | Notes |
|---|---|---|---|
| **VirusTotal** | `VT_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/join-us) | Sign up free → click your profile icon → **API Key**. Also unlocks the URL-scanning VirusTotal provider (same key). Public tier: ~4 requests/min, ~500/day. |
| **MetaDefender** | `METADEFENDER_API_KEY` | [my.opswat.com](https://my.opswat.com/) | Create a free OPSWAT/MetaDefender Cloud account → API key is on your account dashboard. Also unlocks URL reputation/classification. |
| **AlienVault OTX** | `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com/) | Sign up free → **Settings** → **API Integration** shows your key. Also unlocks the OTX URL/domain provider. |
| **MalwareBazaar** | `MB_API_KEY` | [auth.abuse.ch](https://auth.abuse.ch/) | Free abuse.ch "Auth-Key" (a single account covers MalwareBazaar, ThreatFox, *and* URLhaus). Log in → **API Key** page. |
| **ThreatFox** | `THREATFOX_API_KEY` | [auth.abuse.ch](https://auth.abuse.ch/) | Same Auth-Key as MalwareBazaar — paste the identical value here. |
| **Hybrid Analysis** | `HYBRID_API_KEY` | [hybrid-analysis.com](https://www.hybrid-analysis.com/) | Free account → confirm email → **Profile** → **API key**. Also unlocks the URL quick-scan provider. Rate-limited on the free tier. |
| **Triage Sandbox** | `TRIAGE_API_KEY` | [tria.ge](https://tria.ge/) | Free account → **Account** page → **API access**. Hash/file scanning **only** — submitting a *URL* for sandbox detonation returned HTTP 401 on an already-working key (confirmed directly, not a guess), which points at a tier restriction on free/community accounts rather than a bad key, so URL-side Triage isn't offered at all rather than showing a permanently-broken card. |

### URL-scanning-only APIs

| Provider | `config.env` variable | Get a key at | Notes |
|---|---|---|---|
| **URLhaus** | *(reuses `MB_API_KEY`)* | [auth.abuse.ch](https://auth.abuse.ch/) | No separate signup — the same abuse.ch Auth-Key used for MalwareBazaar/ThreatFox also unlocks URLhaus's known-malware-URL database. |
| **OpenPhish** | *(no key)* | [openphish.com](https://openphish.com/) | Nothing to set up — pulls OpenPhish's free community feed of active phishing URLs directly. Used in place of PhishTank, whose API is now behind a Cloudflare bot challenge a plain HTTP client can't pass. Smaller/less complete than a paid feed, but free with zero signup. |
| **IPQualityScore** | `IPQS_API_KEY` | [ipqualityscore.com](https://www.ipqualityscore.com/create-account) | Free account → **Dashboard** → **API Settings** shows your private key. Genuinely free (no card required) but modest: 1,000 lookups/month **and** capped at 35/day — heavy testing/bulk use burns through the daily cap fast and returns "insufficient credits" until it resets, which isn't a sign the key or the free tier is broken. |
| **urlscan.io** | `URLSCAN_API_KEY` | [urlscan.io](https://urlscan.io/user/signup/) | Free account → **Dashboard** → **API** page. Free tier: 50 private / 5,000 public scans per month. This is the provider that supplies the live screenshot shown in URL results. |
| **CheckPhish (Bolster)** | `CHECKPHISH_API_KEY` | [checkphish.ai](https://checkphish.ai/checkphish-api/) | Sign up free → API key is emailed/shown on your dashboard. Free tier: 25 scans/day. |
| **AbuseIPDB** (hosting reputation) | `ABUSEIPDB_API_KEY` | [abuseipdb.com/register](https://www.abuseipdb.com/register) | Free account → **Account** → **API** tab shows your key. Free tier: 1,000 checks/day, no card required. |

### No key required

- **TLS certificate check** — the app connects directly to the site and inspects its certificate chain (verified against your OS's own certificate store, same trust path your browser uses). Always on, instant, unlimited.
- **Certificate Transparency** — tries [SSLMate Certspotter](https://sslmate.com/certspotter/) first (a free, reliable CT-log search API), falling back to crt.sh if Certspotter has nothing. crt.sh alone is a single volunteer-run service that's frequently unreliable under load (it 502s/503s on popular domains often enough that a fallback was worth adding), so it's kept as a backup rather than the primary source.
- **Domain age** — free RDAP lookup (the structured-JSON, IANA-bootstrapped successor to WHOIS), no key, no third-party aggregator.
- **Redirect chain trace** — the app follows redirects itself; no third-party service involved.
- **Brand lookalike / typosquat check** — pure offline string comparison, no network call at all.
- **Favicon match** — the app fetches favicons itself directly; no third-party service.
- **IDN / homoglyph check** — pure offline character-range comparison, no network call at all.
- **URL structure check** — pure offline string/structure checks, no network call at all.
- **Download Content-Type check** — a single HEAD request the app makes itself; no third-party service.
- **SSL Labs deep-dive grade** — free, no key, but rate-limited and slow (~1–2 min); triggered on demand from a button on the URL results panel, not run automatically.

### Not integrated (by design)

Palo Alto PAN-DB and Symantec/Broadcom WebPulse URL categories are **not** queryable through any public API — both are only available live through an appliance you own (a PAN-OS firewall/Panorama's `test url-info-cloud`, or a ProxySG/Edge SWG's Site Review). The composite category shown in URL results is instead merged from VirusTotal/MetaDefender/IPQualityScore as the practical substitute.

**Google Safe Browsing** is also deliberately not integrated: its free v4 Lookup API is licensed for non-commercial use only — any business/enterprise use requires either a commercial agreement with Google or the paid Web Risk API. Its marginal detection value was small on top of what's already here anyway (VirusTotal's 90+ engines already overlap heavily with Safe Browsing's own coverage, and OpenPhish/CheckPhish/IPQualityScore/URLhaus already provide dedicated phishing/malware-URL signal), so it wasn't worth the compliance risk to keep.

---

## Building a standalone .exe

```
python -m PyInstaller --onefile --add-data "templates;templates" --add-data "static;static" --add-data "config.env;." --hidden-import=uvicorn --hidden-import=fastapi --hidden-import=dotenv --name MyFastAPIApp launch_app.py
```
