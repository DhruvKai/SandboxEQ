# 🪲 SandBoxEQ

**Enhanced Multi-API Threat Intelligence Scanner** — a single tool for a security team to answer three questions fast:

1. **Is this file hash/downloaded application malicious?** — fan a hash out across 7 free sandboxes/threat-intel APIs at once, or upload a file for real sandbox detonation.
2. **Is this URL safe?** — fan a URL out across 8 free reputation/category APIs, check its TLS certificate, Certificate Transparency history, domain age/WHOIS, redirect behavior, and brand-lookalike risk, and get a composite **Whitelist / Caution / Block** recommendation — built for two concrete workflows:
   - **Enterprise URL whitelisting** — deciding whether a site should be allowed for the workforce.
   - **Download-source validation** — checking whether the site an application was downloaded from is legitimate, cross-checking the download URL against the file's own hash either way round (via **Advanced Options** on the Single Lookup tab).
3. **Is this IP address trustworthy?** — reputation, abuse history, network/WHOIS ownership, and geolocation for a raw IPv4/IPv6 address, e.g. one you've pulled out of a log file.

All three share one input box — paste a hash, URL, or IP and it's auto-detected and routed to the right engine. Defanged input (`hxxps://evil[.]com`, `8[.]8[.]8[.]8`) is refanged automatically, and a CIDR block like `10.0.0.0/24` opens the offline subnet calculator instead. The **Tools** tab adds a subnet/CIDR calculator and an IOC extractor/defanger, both fully offline.

Everything runs on your own machine against your own API keys.

---

## What it can do

| Tab | What it's for |
|---|---|
| **Single Lookup** | Paste a hash, URL, *or* IP address into one box — auto-detected and routed to the right engine. An **Advanced Options** panel (hash/URL only) lets you additionally give the hash of a downloaded file *and/or* the URL it came from, for download-source-validation cross-checking regardless of which one you put in the main box. Results stream in as each provider finishes rather than waiting on the slowest one. |
| **Digital Certificate** | Choose a Windows executable (`.exe`/`.dll`/`.sys`/...) or an installer (`.msi`) to inspect its digital signature — publisher, issuing CA, validity, a **Timestamp Information** card, and tamper status. Each result has one-click **Copy certificate summary** and **Copy timestamp summary** buttons. See [Digital Certificate tab](#digital-certificate-tab-in-detail). |
| **Tools** | Two offline utilities (no API keys needed). **Subnet / CIDR Calculator**: network, netmask, wildcard, broadcast, usable range and host count, address scope (private/public/CGNAT/...), reverse-DNS zone, split into smaller subnets, "is this IP/CIDR inside it?", and summarize/range-to-CIDR merging; IPv4 and IPv6. **IOC Extractor / Defang**: paste an email or report (defanged or not) and pull out URLs, IPs, domains, emails, hashes, and CVE IDs, with one-click lookups, refang/defang of the whole text, and a CSV export for Bulk Analysis. |
| **Bulk Analysis** | Upload a CSV of hashes and/or URLs (column named `hash`, `url`, `indicator`, `value`, or `ioc`) for batch scanning, with a downloadable CSV of results. |
| **Sandbox Upload** | Upload a real file to VirusTotal, MetaDefender, Hybrid Analysis, and/or Triage for full sandbox detonation, with live progress. |
| **Settings** | Enter/update API keys, split into a **Hash/File Scanning APIs** sub-tab, a **URL Scanning APIs** sub-tab, and an **IP Lookup APIs** sub-tab. Keys are stored locally in `config.env`; blank fields keep whatever's already saved. |
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
| 📡 **GreyNoise** | Is this IP just internet background noise? Flags mass scanners/crawlers (classified benign or malicious) and well-known business services (RIOT). "Noise" means opportunistic scanning, so traffic from it is unlikely to be aimed at you; *not* seen by GreyNoise means it isn't a mass scanner, so if it's hitting you it may be targeted. Works with no key (~10 lookups/day); an optional free key raises that. |
| 🔎 **Shodan InternetDB** | What Shodan has passively observed on the IP: open ports, detected software (CPEs), tags (`scanner`, `vpn`, `self-signed`, ...), hostnames, and known CVEs. A snapshot, not a live scan. |

The GreyNoise and Shodan cards are informational, like AbuseIPDB and WHOIS: they don't feed the threat score. The WHOIS card lists the network's CIDR blocks as buttons that open the subnet calculator.

---

## New features in detail

### Subnet / CIDR calculator (Tools tab)

Type a network into **Tools → Subnet / CIDR Calculator** and click **Calculate**. It needs no API keys and makes no network calls. You can also paste a CIDR straight into the main search box on the Single Lookup tab (for example `10.0.0.0/24`) and it opens the calculator for you instead of trying to look it up as a hash.

**Accepted input**

| You type | Meaning |
|---|---|
| `192.168.1.0/24` | Standard CIDR |
| `192.168.1.77/24` | An address with host bits set — the calculator shows the network it belongs to (`192.168.1.0/24`) and warns you that you gave a host address |
| `10.0.0.0/255.255.255.0` or `10.0.0.0 255.255.255.0` | Address with a subnet mask |
| `10.0.0.0 0.0.0.255` | Address with a wildcard (inverse) mask |
| `8.8.8.8` | A single host (`/32`, or `/128` for IPv6) |
| `10.0.0.0 - 10.0.0.255` | A start–end range, accepted only if it is exactly one CIDR block |
| `2001:db8::/32` | IPv6 |
| `10[.]0[.]0[.]0/8` | Defanged input is refanged automatically |

**What you get back** (click any value to copy it)

| Field | Meaning |
|---|---|
| Network / Netmask / Wildcard mask / Broadcast | The block's identity and its masks (IPv4). IPv6 shows the compressed and exploded forms and the last address instead |
| First / last usable host, Usable hosts | The assignable range. A `/31` reports 2 usable hosts (point-to-point links, RFC 3021), a `/32` reports 1, and everything else excludes the network and broadcast addresses |
| Total addresses | Includes the power of two, e.g. `8,388,608 (2^23)` |
| Address scope | Private (RFC 1918), shared/carrier-grade NAT (`100.64.0.0/10`), loopback, link-local, multicast, documentation ranges, reserved, unique-local (IPv6) or **Public / globally routable**. A block that only partly overlaps a special range (like `8.0.0.0/5`, which contains `10.0.0.0/8`) is reported as *spans several address types* rather than guessed at |
| Binary netmask | The mask in binary, for checking a subnetting exercise by eye |
| Reverse DNS zone | The `in-addr.arpa` / `ip6.arpa` zone, shown when the prefix falls on an octet (IPv4) or nibble (IPv6) boundary |
| Hosts | For blocks of 16 addresses or fewer, every host is listed. If the block is public, each one has a 🔍 button that runs a normal IP lookup on it. Larger blocks are deliberately not offered, so a `/24` can't burn through your daily API quotas |

**Split into /…** — divides the block into smaller, equal-sized subnets. Enter the new prefix length (it must be longer than the current one, and at most 32 for IPv4 or 128 for IPv6). Each extra bit doubles the number of subnets and halves the size of each. Splitting `100.128.0.0/9` into `/11` (two extra bits) gives 2² = 4 subnets — `100.128.0.0/11`, `100.160.0.0/11`, `100.192.0.0/11`, `100.224.0.0/11` — each with 2,097,150 usable hosts. The table lists every subnet with its first host, last host and usable count. For very large splits (a `/9` into `/24`s is 32,768 subnets) it shows the first 256 and tells you the exact total. It only produces equal-sized pieces, so it is not a variable-length (VLSM) planner.

**Is this IP / CIDR inside it?** — enter an address or another block to get *inside*, *not inside*, *fully contains*, *overlaps* or *does not overlap*. Useful for checking whether an address from a log falls inside a firewall range.

**Summarize / range to CIDR** — paste any number of CIDR blocks, single IPs and `start - end` ranges (one per line or comma-separated). It merges them into the fewest CIDR blocks that cover exactly the same addresses, handles IPv4 and IPv6 separately, and lists any lines it couldn't read instead of failing the whole batch. `10.0.0.0/25` plus `10.0.0.128/25` becomes `10.0.0.0/24`; an awkward range such as `192.168.1.1 - 192.168.1.4` becomes `192.168.1.1/32`, `192.168.1.2/31` and `192.168.1.4/32`.

**Connection to IP lookups** — the *IP WHOIS / Network* card turns the registry's start–end range into CIDR blocks, shown as buttons. Click one to open it in the calculator.

### IOC extractor and defang (Tools tab)

Paste an email, report, log or any block of text into **Tools → IOC Extractor / Defang**. It works on defanged and normal text alike.

**Extract IOCs** finds and de-duplicates (keeping first-seen order):

| Category | Notes |
|---|---|
| URLs | `http`, `https`, `ftp`. Trailing sentence punctuation is trimmed, and a closing `)` is kept only when it balances an opening one (so `page_(1)` survives but `(see http://a.com/x)` doesn't swallow the bracket) |
| IPv4 / IPv6 | Validated, not just pattern-matched. Each carries a scope tag (`private`, `loopback`, `link-local`...); public ones get a lookup button, private ones don't. IPv4 with leading zeros is skipped as ambiguous |
| Domains | Also includes the host of every URL and the domain of every email address. See the limits below |
| Email addresses | Lower-cased |
| MD5 / SHA-1 / SHA-256 / SHA-512 | Identified by length; all-digit runs are ignored as numbers. SHA-512 can be extracted and copied but has no lookup button, since the hash lookup supports MD5, SHA-1 and SHA-256 |
| CVE IDs | Upper-cased, each linking to the NVD entry |

**Refang** undoes the common defanging conventions: `hxxp` / `hXXp` / `h**p`, `[.]` `(.)` `{.}` `[dot]`, `[://]` `[:]` `[/]`, `[@]` `[at]`, and backslash-escaped dots. **Defang text** does the reverse on every indicator it finds — scheme `hxxps`, `[://]`, dots in the host as `[.]`, `[@]` in emails — leaving URL paths readable. Tick **Show / copy defanged** to view or copy the extracted lists in defanged form, safe to paste into email or chat. The main search box on the Single Lookup tab also refangs whatever you paste, so `hxxps://evil[.]com` and `8[.]8[.]8[.]8` just work.

Each extracted URL, public IP and MD5/SHA-1/SHA-256 has a **🔍 Look up** button that runs the normal Single Lookup. Domains are looked up as `https://<domain>`. **CSV for Bulk Analysis** downloads the URLs and hashes as a file ready for the Bulk Analysis tab.

**Limits to know about.** Domain extraction is deliberately conservative so that filenames and code don't flood the list: names ending in `.exe`, `.js`, `.py`, `.sh`, `.md`, `.so` and similar are skipped, and a domain is only accepted if its TLD is a two-letter country code, a punycode (`xn--`) TLD, or one of a built-in list of common generic TLDs (including the cheap ones abused for phishing, like `.top`, `.xyz` and `.click`). A real domain on an unusual new TLD can therefore be missed. Domains inside a URL or email are still captured through that URL or email.

### GreyNoise and Shodan InternetDB cards (IP lookups)

Both appear alongside VirusTotal, AbuseIPDB, WHOIS and Geolocation when you look up an IP. They are informational: like AbuseIPDB and WHOIS, they don't feed the threat score.

**📡 GreyNoise** answers *"is this IP just internet background noise?"*

| What you see | What it means |
|---|---|
| ✔️ **Benign scanner**, "Identified as: Shodan.io" | A known, documented scanner or crawler. Traffic from it is opportunistic, not aimed at you |
| ❌ **Malicious internet scanner** | Mass-scanning the internet with hostile behaviour (brute-forcing, exploit attempts). Still opportunistic — it says little about whether it is targeting *you* specifically |
| ⚠️ **Internet scanner (unclassified)** | Seen scanning, but not classified either way |
| ✔️ **Common business service (RIOT)** | A well-known service such as a public DNS resolver, CDN or SaaS provider |
| *"Not seen scanning the internet"* | Not mass-scanner noise. If it is hitting your network, it may be targeted — treat that as more interesting, not less |

It works with no key but is limited to about 10 lookups a day. A free `GREYNOISE_API_KEY` (business-email signup, 50 lookups a week) can be added under **Settings → IP Lookup APIs**. When the limit is hit, the card says so instead of showing a generic error. GreyNoise only covers public addresses; a private IP gets a plain "public IPs only" note.

**🔎 Shodan InternetDB** shows what Shodan has passively observed on the address: **open ports**, **known CVEs** (red chips linking to the NVD), detected **software** (CPEs), **tags** (`scanner`, `vpn`, `self-signed`, `starttls`...) and reverse-DNS **hostnames**. It needs no key. It is a periodically refreshed snapshot, not a live scan, so a port that isn't listed isn't proof it's closed, and "no data" means Shodan hasn't seen the address.

*Licensing note:* the terms of use for Shodan InternetDB and the GreyNoise community tier were not verified when these cards were added. Check them before relying on either in a commercial or enterprise setting (the same kind of caution that led to Google Safe Browsing being left out, below).

### Digital Certificate tab in detail

Choose a file on the **Digital Certificate** tab. It accepts Windows executables (`.exe`, `.dll`, `.sys`, ...) and Windows Installer packages (`.msi`). Each embedded signature gets:

- **Cert Information** — signer, validity range, issuing CA, a status badge (valid / expired / known abused certificate) and an **Integrity** line. A **📋 Copy certificate summary** button copies:

  ```
  Signer: Microsoft Corporation
  Issuer (CA): Microsoft Code Signing PCA 2011
  Valid to: 26 Jul 2019
  ```

- **Timestamp Information** — its own card: when the signature was countersigned, which timestamp authority (TSA) did it, that authority's issuing CA, and when the TSA's own certificate expires. A **📋 Copy timestamp summary** button copies:

  ```
  Timestamped at: Wed, 24 Oct 2018 03:32:19 UTC
  Timestamp authority: Microsoft Time-Stamp service
  Issuer (CA): Microsoft Time-Stamp PCA
  Valid to: 23 Nov 2019
  ```

  The two examples above are from the same file, and show why the timestamp matters: the signing certificate expired in July 2019, but the signature was timestamped in October 2018 while that certificate was still valid, so it remains trustworthy. A signature with **no** timestamp stops being trustworthy the day its certificate expires, and the card says so.
- **More details** — the full signer and TSA certificates (serial, thumbprints, key algorithm, extended key usage), the issuing chain, the embedded and recomputed file digests, and the program name the signer declared. For dual SHA-1 + SHA-256 signed files, every signature is shown, with an *Embedded Signatures* summary table on top.
- **Export CSV** — every certificate (signer, CA chain, timestamp authority) as one CSV.

**Integrity check.** The file's digest is recomputed and compared with the digest sealed inside the signature. *✅ Matches file* means nothing in the signed part has changed since signing; *❌ MISMATCH* means the file was modified after signing or the signature is invalid — treat it as untrusted. *⚠️ Unverified* means the digest couldn't be reproduced (for example an unsupported hash algorithm); that is never reported as tampering. For an `.msi` the digest covers the package's internal streams in Windows Installer order. The parser was checked against 145 signed installers (27 SHA-1, 118 SHA-256, with and without the extended-signature stream) and 5 unsigned ones already on a Windows machine: every signer thumbprint and integrity result agreed with Windows' own verdict. A deliberately altered copy was flagged as a mismatch, which is also what Windows reports for it.

**Why `.msi` needed special handling.** An `.msi` is not a PE file. It is an OLE compound file, and its signature is not appended like an `.exe`'s but stored in a hidden stream named `DigitalSignature` inside it. The tab reads that stream and then treats it exactly like an executable's signature.

---

## Worked examples

These use inputs that were run while building the features. Live results (last-seen dates, port lists, VirusTotal verdicts) change over time, so treat the details as what to expect rather than exact text.

### IP lookups

| Type into the search box | What to expect |
|---|---|
| `71.6.135.131` | GreyNoise: **Benign scanner — "Identified as: Shodan.io"**, with a recent *Last seen* date. Shodan InternetDB: ports **22, 4500, 9002**, tags **`scanner`** and **`vpn`**, and several `soda.census.…` hostnames. IP WHOIS: `71.6.135.0 - 71.6.135.255` shown as the CIDR button **`71.6.135.0/24 🧮`** — click it to jump to the subnet calculator. With a VirusTotal key set, VirusTotal may also flag it (scanners often get reported); only VirusTotal counts towards the threat score, so the GreyNoise and Shodan cards give context rather than a verdict |
| `71[.]6[.]135[.]131` | Exactly the same result — demonstrates defanged input being accepted |
| `8.8.8.8` | Shodan InternetDB: ports **53** and **443**, hostname **`dns.google`**. GreyNoise: *not seen scanning the internet* |
| `81.182.244.49` | A mail/web server: Shodan shows ports **25, 80, 443**, tags **`self-signed`** and **`starttls`**, and detected software including Microsoft Exchange Server |
| `192.168.1.1` | A private address: no red errors — Shodan says it has no data and GreyNoise says it only covers public IPs |
| `203.0.113.7` | A documentation-range address (reserved for examples): both cards return a "no data" style note |

No IP with known CVEs is included here, so the red CVE chips on the Shodan card are the one part not demonstrated by these examples.

### Subnet calculator

| Network (and options) | What to expect |
|---|---|
| `192.168.1.77/24`, *inside it?* `192.168.1.200`, *split into* `26` | A warning that `192.168.1.77` is a host address; network `192.168.1.0/24`, netmask `255.255.255.0`, broadcast `192.168.1.255`, 254 usable hosts; **"192.168.1.200 is inside 192.168.1.0/24"**; four `/26` subnets — `192.168.1.0/26`, `.64/26`, `.128/26`, `.192/26` |
| `100.128.0.0/9` | **Public / globally routable**, 8,388,606 usable hosts, 8,388,608 total (2^23) |
| `100.64.0.0/10` | The neighbouring range, labelled **shared address space / carrier-grade NAT** — easy to mistake for `100.128.0.0/9` |
| `100.128.0.0/9`, *split into* `11` | 4 subnets of 2,097,150 usable hosts each (see the split explanation above) |
| `192.168.1.0/29` | Private; lists all 6 usable hosts |
| `8.8.8.0/29` | Public; lists 6 hosts, each with a 🔍 lookup button |
| `10.0.0.0/31` | 2 usable hosts (point-to-point link) |
| `8.0.0.0/5` | **Spans several address types** (it contains `10.0.0.0/8`) |
| `2001:db8::/32` | IPv6 documentation range; reverse zone `8.b.d.0.1.0.0.2.ip6.arpa`; 4,294,967,296 `/64` networks inside |
| `10.0.0.1 - 10.0.0.9` | An error explaining the range needs 4 blocks (`10.0.0.1/32`, `10.0.0.2/31`, `10.0.0.4/30`, `10.0.0.8/31`) — use the Summarize box for ranges |

**Summarize box.** Paste:

```
10.0.0.0/25
10.0.0.128/25
192.168.1.1 - 192.168.1.4
2001:db8::/33
2001:db8:8000::/33
not-an-ip
```

Result: 6 entries merged into `10.0.0.0/24`, `192.168.1.1/32`, `192.168.1.2/31`, `192.168.1.4/32` and `2001:db8::/32`, with `not-an-ip` listed as skipped.

### IOC extractor

Paste this into **Tools → IOC Extractor / Defang**:

```
C2 callback to hxxps://evil[.]example[.]com/gate.php, also 45[.]33[.]32[.]156 and 10.1.2.3.
Phish from bad.actor[@]mail-evil[.]top. Dropped update.exe and script.py.
MD5 d41d8cd98f00b204e9800998ecf8427e
SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Exploits CVE-2024-3094 and CVE-2021-44228.
```

**Extract IOCs** finds 10 indicators: **1 URL** (`https://evil.example.com/gate.php`), **2 IPv4 addresses** (`45.33.32.156`, and `10.1.2.3` tagged *private* with no lookup button), **2 domains** (`evil.example.com`, `mail-evil.top`), **1 email** (`bad.actor@mail-evil.top`), **1 MD5**, **1 SHA-256** and **2 CVE IDs**. `update.exe` and `script.py` are correctly ignored as filenames. **Defang text** turns the first line into `C2 callback to hxxps[://]evil[.]example[.]com/gate.php, also 45[.]33[.]32[.]156 and 10[.]1[.]2[.]3.` **CSV for Bulk Analysis** contains the URL and the two hashes.

### Digital Certificate tab

Any signed Microsoft `.msi` works well — for instance the .NET or Visual C++ redistributable installers that already sit in `C:\ProgramData\Package Cache` or `C:\Windows\Installer` on most Windows machines. Choose one and you should see the **Cert Information** and **Timestamp Information** cards, *✅ Matches file*, and the two copy buttons. Compare an older installer (its signing certificate has usually expired, but the timestamp keeps the signature valid) with a recent one to see the difference the timestamp makes.

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
- **Subnet / CIDR calculator and IOC extractor / defang** (Tools tab) — pure offline computation, no network calls.
- **Shodan InternetDB** — free, keyless passive lookup at [internetdb.shodan.io](https://internetdb.shodan.io/). Its usage terms were not verified when this card was added — check them before relying on it in a commercial/enterprise setting (the same licensing caution that led to Google Safe Browsing being left out, below).
- **GreyNoise Community API** — works keyless (~10 lookups/day). An optional free `GREYNOISE_API_KEY` (business-email signup; 50 lookups/week) can be set in **Settings → IP Lookup APIs**. Check GreyNoise's terms for commercial use too; they were not verified when this card was added.
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
