# 🪲 SandBoxEQ

**Enhanced Multi-API Threat Intelligence Scanner** — a single tool for a security team to answer three questions fast:

1. **Is this file hash/downloaded application malicious?** — fan a hash out across 7 free sandboxes/threat-intel APIs at once, or upload a file for real sandbox detonation.
2. **Is this URL safe?** — fan a URL out across 8 free reputation/category APIs, check its TLS certificate, Certificate Transparency history, domain age/WHOIS, redirect behavior, and brand-lookalike risk, and get a composite **Whitelist / Caution / Block** recommendation — built for two concrete workflows:
   - **Enterprise URL whitelisting** — deciding whether a site should be allowed for the workforce.
   - **Download-source validation** — checking whether the site an application was downloaded from is legitimate, cross-checking the download URL against the file's own hash either way round (via **Advanced Options** on the Single Lookup tab).
3. **Is this IP address trustworthy?** — reputation, abuse history, network/WHOIS ownership, and geolocation for a raw IPv4/IPv6 address, e.g. one you've pulled out of a log file.

All three share one input box — paste a hash, URL, or IP and it's auto-detected and routed to the right engine.

Everything runs locally against your own API keys — no file contents, URLs, or IPs are sent anywhere except the threat-intel providers you've configured, and only when you run a lookup.

---

## What it can do

| Tab | What it's for |
|---|---|
| **Single Lookup** | Paste a hash, URL, *or* IP address into one box — auto-detected and routed to the right engine. An **Advanced Options** panel (hash/URL only) lets you additionally give the hash of a downloaded file *and/or* the URL it came from, for download-source-validation cross-checking regardless of which one you put in the main box. Results stream in as each provider finishes rather than waiting on the slowest one. |
| **Digital Certificate** | Drop a Windows executable (`.exe`/`.dll`/`.sys`/`.msi`) to inspect its Authenticode signature — publisher, issuing CA, validity, tamper status. Parsed **entirely in your browser**; the file is never uploaded. |
| **Bulk Analysis** | Upload a CSV of hashes and/or URLs (column named `hash`, `url`, `indicator`, `value`, or `ioc`) for batch scanning, with a downloadable CSV of results. |
| **Sandbox Upload** | Upload a real file to VirusTotal, MetaDefender, Hybrid Analysis, and/or Triage for full sandbox detonation, with live progress. |
| **Settings** | Enter/update API keys, split into a **Hash/File Scanning APIs** sub-tab and a **URL Scanning APIs** sub-tab. Keys are stored locally in `config.env`; blank fields keep whatever's already saved. |
| **Terminal** | Live, plain-text log of every provider call as a scan runs, with a one-click **Copy** button. Automatically clears at the start of each new scan rather than piling up behind the previous one. |
| **History & Bookmarks** | Recent searches and saved lookups, with one-click re-scan. |

Every provider is optional — the app only queries whichever keys you've configured, and continues normally (with a "not configured" skip, or a per-provider error card) around the ones you haven't.

---

## Result cards, explained

Below is every card the app can show today, grouped by which kind of lookup produces it. If a provider isn't configured (or was intentionally left out — see the API key tables further down), its card simply doesn't appear rather than showing an error.

### Hash lookup cards

| Card | What it's for |
|---|---|
| 🛡️ **VirusTotal** | Aggregates verdicts from 90+ antivirus/security engines against this exact file hash — the broadest single signal available. |
| 🛡️ **MetaDefender** | A second, independent multi-engine aggregator (OPSWAT) — a different engine mix than VirusTotal, useful as a cross-check rather than a duplicate. |
| 👁️ **OTX AlienVault** | AlienVault's threat-intelligence "pulses" — community/vendor-submitted reports that reference this hash (campaigns, malware families, IOC lists it's been seen in). |
| 🦠 **MalwareBazaar** | abuse.ch's dedicated malware-sample database — confirms whether this exact hash is a known, catalogued malware sample, with family/tag info. |
| 🦊 **ThreatFox** | abuse.ch's indicator-of-compromise (IOC) database — checks whether this hash has been reported as part of an active malware campaign. |
| 🔬 **Hybrid Analysis** | CrowdStrike's public sandbox database — shows whether this hash has already been detonated and analyzed, with a behavioral verdict. |
| 🏥 **Triage Sandbox** | Hatching Triage's public sandbox database — another independent detonation-report source. Hash lookups only (see the API key table below for why URLs aren't sent to Triage). |

### URL lookup cards

**Reputation/verdict engines** — the same idea as the hash cards above, applied to the URL itself:

| Card | What it's for |
|---|---|
| 🛡️ **VirusTotal** | Multi-engine verdict for the URL, plus its detected content category. |
| 🔰 **MetaDefender** | Second independent multi-engine URL verdict/category. |
| 🌐 **OTX AlienVault** | Threat-intel pulses/reports referencing this URL or its domain. |
| 🧨 **URLhaus** | abuse.ch's dedicated malware-distribution-URL database. |
| 🧪 **Hybrid Analysis** | Quick URL scan against CrowdStrike's public sandbox database. |
| 🎣 **OpenPhish** | Checked against OpenPhish's live community feed of active phishing URLs. |
| 🕵️ **CheckPhish** | Bolster's deep-learning visual phishing/brand-impersonation detector. |
| 🖼️ **urlscan.io** | A live, real browser-rendered scan of the page — screenshot, the final URL after any redirects/JavaScript, and a verdict score. The screenshot is the fastest way to see what a link actually shows before you visit it yourself. |

**Site legitimacy / infrastructure checks** — mostly free and keyless, always run for any URL:

| Card | What it's for |
|---|---|
| 🔒 **TLS Certificate** | Connects to the site directly and inspects its HTTPS certificate: is it currently valid (not expired), is it issued by a CA your OS actually trusts, and does the chain check out. A failed or self-signed certificate is a strong red flag on its own, before any reputation engine has even weighed in. |
| 📜 **Certificate Transparency (crt.sh)** | Every publicly-trusted TLS certificate ever issued for a domain gets logged in public, auditable Certificate Transparency logs. This card searches those logs (via SSLMate Certspotter, falling back to crt.sh) — useful for spotting a certificate issued for a domain that its legitimate owner never requested, or an unusually large/suspicious issuance history. |
| 🪪 **WHOIS / Domain Age** | Registration date, expiration date, last-changed date, registrar, the registrar's abuse-report contact email, and nameservers — via a free RDAP lookup (WHOIS's modern, structured-data successor). A domain registered days ago is one of the strongest "this could be a disposable phishing/malware domain" signals there is. Registrant/admin contact details are almost always redacted for privacy under modern RDAP policy, so registrar + nameservers are typically the only reliably public fields. |
| ↪️ **Redirect Chain** | Follows every redirect hop by hop (not just the final landing page) and flags it when the URL routes through a *different domain* before landing — a common trick for disguising the real destination. |
| 🪪 **Brand Lookalike Check** | Instant, offline comparison against a built-in list of commonly-impersonated brands (Microsoft, Google, PayPal, major banks, ...) — catches near-miss typosquats like `microsft.com`. |
| 🖇️ **Favicon Match** | Fetches the site's favicon and, when the Brand Lookalike check above already flagged a close match, fetches that brand's real favicon too and compares them. An exact match on a domain that *isn't* the real brand is hard evidence of a cloned phishing kit, not just a coincidentally similar name. |
| 🔤 **IDN / Homoglyph Check** | Flags internationalized domain names that mix in a script commonly used to spoof Latin letters (Cyrillic "а" instead of Latin "a", etc.) — catches lookalike attacks that slip straight past the plain-ASCII Brand Lookalike check above. |
| 🧩 **URL Structure Check** | Instant, offline red-flag scan of the URL's shape itself: a raw IP address as the host, an `@` symbol before the host (a classic destination-disguising trick), unusually deep subdomain nesting, a disproportionately-abused TLD (`.tk`, `.top`, `.xyz`, ...), a known URL shortener, or an unusually long URL. |
| 📦 **Download Content-Type Check** | For a URL that looks like a direct file download (ends in `.exe`, `.zip`, `.msi`, etc.), sends a HEAD request to confirm the server is actually serving that file type. An installer link that serves back an HTML page is very often a dead link or a gate/landing page, not the real download. |
| 🌐 **Hosting Reputation (AbuseIPDB)** | Resolves the domain to its hosting IP and checks that IP against AbuseIPDB's abuse-report history — a signal about the infrastructure itself, independent of anything about the domain name. Catches campaigns reusing known "bulletproof"/abused hosting even before the domain has been reported anywhere. |
| 🔗 **Download Cross-Check** | Only appears when you've used **Advanced Options** (Single Lookup tab) to pair a hash with a download URL — checks VirusTotal's record of files actually seen downloaded from that URL for a match against the hash you gave, confirming (or disproving) that the file really came from where you think it did. |
| **Composite Verdict banner** | Not a provider card — a summary built from everything above: category + risk score + certificate status + every signal on the page, rolled into one **✅ Whitelist / ⚠️ Caution – Manual Review / 🚫 Block** recommendation. |

### IP lookup cards

| Card | What it's for |
|---|---|
| 🛡️ **VirusTotal** | Multi-engine reputation verdict for the IP address itself, plus its country and network/AS owner. |
| 🚫 **AbuseIPDB** | Abuse-confidence score and report count for this exact IP over the last 90 days, plus its ISP and any domain AbuseIPDB associates with it. |
| 🪪 **IP WHOIS / Network** | Network allocation details via a free RDAP lookup — the IP range/CIDR block it belongs to, the allocation type, the owning organization, and the network's registry handle. |
| 🌍 **Geolocation / Reverse DNS** | Country/region/city, ISP, network/AS owner, and the PTR (reverse DNS) hostname the IP resolves back to — free, keyless geolocation via ip-api.com. |

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
| **VirusTotal** | `VT_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/join-us) | Sign up free → click your profile icon → **API Key**. Also unlocks the URL- and IP-scanning VirusTotal cards (same key, one signup). Public tier: ~4 requests/min, ~500/day. |
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
| **urlscan.io** | `URLSCAN_API_KEY` | [urlscan.io](https://urlscan.io/user/signup/) | Free account → **Dashboard** → **API** page. Free tier: 50 private / 5,000 public scans per month. This is the provider that supplies the live screenshot shown in URL results. |
| **CheckPhish (Bolster)** | `CHECKPHISH_API_KEY` | [checkphish.ai](https://checkphish.ai/checkphish-api/) | Sign up free → API key is emailed/shown on your dashboard. Free tier: 25 scans/day. |
| **AbuseIPDB** (hosting reputation / IP checks) | `ABUSEIPDB_API_KEY` | [abuseipdb.com/register](https://www.abuseipdb.com/register) | Free account → **Account** → **API** tab shows your key. Free tier: 1,000 checks/day, no card required. Same key powers both the URL lookup's "Hosting Reputation" card and the IP lookup's "AbuseIPDB" card. |
| ~~**IPQualityScore**~~ | `IPQS_API_KEY` | [ipqualityscore.com](https://www.ipqualityscore.com/create-account) | **Not currently queried** — the free tier's daily cap (35/day) ran out consistently in practice and returned "insufficient credits" on most scans, so it was removed from the URL lookup rather than showing a permanently-broken card. The Settings field is still there and the key still gets saved if you paste one in, in case this gets re-enabled later (e.g. on a paid tier). |

### No key required

- **TLS certificate check** — the app connects directly to the site and inspects its certificate chain (verified against your OS's own certificate store, same trust path your browser uses). Always on, instant, unlimited.
- **Certificate Transparency** — tries [SSLMate Certspotter](https://sslmate.com/certspotter/) first (a free, reliable CT-log search API), falling back to crt.sh if Certspotter has nothing. crt.sh alone is a single volunteer-run service that's frequently unreliable under load (it 502s/503s on popular domains often enough that a fallback was worth adding), so it's kept as a backup rather than the primary source.
- **WHOIS / domain age** — free RDAP lookup (the structured-JSON, IANA-bootstrapped successor to WHOIS), no key, no third-party aggregator. The same free RDAP service also powers the IP lookup's **IP WHOIS / Network** card.
- **Redirect chain trace** — the app follows redirects itself; no third-party service involved.
- **Brand lookalike / typosquat check** — pure offline string comparison, no network call at all.
- **Favicon match** — the app fetches favicons itself directly; no third-party service.
- **IDN / homoglyph check** — pure offline character-range comparison, no network call at all.
- **URL structure check** — pure offline string/structure checks, no network call at all.
- **Download Content-Type check** — a single HEAD request the app makes itself; no third-party service.
- **IP geolocation / reverse DNS** — free, keyless lookup via [ip-api.com](https://ip-api.com/) (45 requests/minute on the free tier — plenty for interactive single lookups).
- **SSL Labs deep-dive grade** — free, no key, but rate-limited and slow (~1–2 min); triggered on demand from a button on the URL results panel, not run automatically.

### Not integrated (by design)

Palo Alto PAN-DB and Symantec/Broadcom WebPulse URL categories are **not** queryable through any public API — both are only available live through an appliance you own (a PAN-OS firewall/Panorama's `test url-info-cloud`, or a ProxySG/Edge SWG's Site Review). The composite category shown in URL results is instead merged from VirusTotal/MetaDefender as the practical substitute.

**Google Safe Browsing** is also deliberately not integrated: its free v4 Lookup API is licensed for non-commercial use only — any business/enterprise use requires either a commercial agreement with Google or the paid Web Risk API. Its marginal detection value was small on top of what's already here anyway (VirusTotal's 90+ engines already overlap heavily with Safe Browsing's own coverage, and OpenPhish/CheckPhish/URLhaus already provide dedicated phishing/malware-URL signal), so it wasn't worth the compliance risk to keep.

---

## Building a standalone .exe

```
python -m PyInstaller --onefile --add-data "templates;templates" --add-data "static;static" --add-data "config.env;." --hidden-import=uvicorn --hidden-import=fastapi --hidden-import=dotenv --name MyFastAPIApp launch_app.py
```
