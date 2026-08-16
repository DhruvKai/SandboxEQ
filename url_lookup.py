#!/usr/bin/env python3
"""
SandBoxEQ - URL Scanning Engine

Mirrors hash_lookup.py's provider/plugin pattern (BaseAPI, one class per
threat-intel provider, a *Tool class that fans a lookup out to every
configured provider concurrently) but for URLs instead of file hashes.
See hash_lookup.py for the hash-scanning half and the shared BaseAPI
contract (is_configured() / _get_session() / close_session()) both halves
build on.

Every provider's query_url() returns the same normalized shape used
throughout the app: {'malicious': bool, 'not_found': bool, 'error': str,
'report_link': str, ...provider-specific extras}.
"""

import asyncio
import base64
import hashlib
import ipaddress
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import quote, urljoin, urlparse

import aiohttp
from dotenv import load_dotenv

import config_store
from hash_lookup import (
    BaseAPI,
    HybridAnalysisAPI,
    MetaDefenderAPI,
    OTXAlienVaultAPI,
    VirusTotalAPI,
    build_log_text,
    _new_ssl_context,
    _exc_text,
    strip_hash_label,
)

# File extensions that mark a URL as a direct file download link. Used by
# app.py to decide whether the Single Lookup form should offer the optional
# "hash to cross-check" field (the download-source-validation use case).
DOWNLOAD_FILE_EXTENSIONS = (
    '.exe', '.msi', '.zip', '.dmg', '.pkg', '.7z', '.rar', '.appimage',
    '.deb', '.rpm', '.apk', '.bin', '.iso', '.jar',
)


def _is_valid_url(value: str) -> bool:
    """Basic http(s) URL validation - mirrors _is_valid_hash's role in hash_lookup.py."""
    if not value:
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme in ('http', 'https') and bool(parsed.netloc)


def is_direct_file_link(url: str) -> bool:
    """True when the URL's path looks like a direct download of a file."""
    try:
        path = urlparse(url).path.lower()
    except ValueError:
        return False
    return path.endswith(DOWNLOAD_FILE_EXTENSIONS)


# --- Offline heuristics (no network call, no API key) -----------------------

# Unicode ranges for scripts most commonly used in homograph/IDN phishing
# attacks - individual characters in these ranges have look-identical
# counterparts in Latin (Cyrillic а/е/о/р/с/у/х vs Latin a/e/o/p/c/y/x, etc.).
# Not exhaustive - just the scripts that account for the overwhelming
# majority of real-world IDN homograph attacks.
_CONFUSABLE_SCRIPT_RANGES = (
    (0x0400, 0x04FF),  # Cyrillic
    (0x0500, 0x052F),  # Cyrillic Supplement
    (0x0370, 0x03FF),  # Greek and Coptic
)


def _is_confusable_char(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _CONFUSABLE_SCRIPT_RANGES)


def check_idn_homoglyph(hostname: str) -> Dict[str, Any]:
    """Flags internationalized domain names, and specifically ones mixing
    in a script commonly used to spoof Latin lookalikes (Cyrillic 'а' vs
    Latin 'a', etc.) - a technique that slips past the plain-ASCII
    edit-distance typosquat check entirely, since to that check the string
    already doesn't look like the brand it's impersonating. Handles both a
    punycode-encoded hostname (xn--...) and one pasted directly in Unicode."""
    labels = hostname.split('.')
    decoded = None

    if any(label.startswith('xn--') for label in labels):
        try:
            decoded = hostname.encode('ascii').decode('idna')
        except Exception:
            decoded = None
    elif not hostname.isascii():
        decoded = hostname

    if decoded is None:
        return {'is_idn': False}

    suspicious = [ch for ch in decoded if _is_confusable_char(ch)]
    result = {'is_idn': True, 'decoded': decoded}
    if suspicious:
        result['warning'] = (
            "Internationalized domain mixes in a script commonly used to spoof Latin lookalikes "
            "(e.g. Cyrillic 'а' vs Latin 'a') - verify this is really the site you expect"
        )
    else:
        result['context'] = 'Internationalized domain name (non-Latin script) - not inherently malicious, but worth a second look'
    return result


# TLDs that see disproportionate phishing/malware abuse relative to their
# size - mostly free or very-cheap-to-register registries. Not a
# blocklist by itself (plenty of legitimate sites use these), just one
# input into the composite verdict.
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq',  # Freenom's free ccTLDs - historically the most abused set
    'top', 'xyz', 'club', 'work', 'support', 'buzz', 'rest', 'fit',
    'loan', 'win', 'bid', 'stream', 'review', 'party', 'trade',
    'accountant', 'science', 'men', 'date', 'download', 'click', 'link',
    'icu', 'cam', 'cyou', 'sbs',
}

# Common URL-shortener domains - not inherently malicious, but they hide
# the real destination from a quick glance, so worth flagging explicitly
# alongside the redirect-chain trace that reveals where they actually go.
URL_SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 't.ly', 'rb.gy',
    'v.gd', 'bl.ink', 's.id',
}


def check_url_heuristics(url: str) -> Dict[str, Any]:
    """A grab-bag of instant, offline structural red flags - none of these
    alone proves anything, but each is a well-known trick and costs
    nothing to check."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or '').lower()
    flags = []

    is_ip_host = False
    try:
        ipaddress.ip_address(hostname)
        is_ip_host = True
        flags.append('Host is a raw IP address rather than a domain name')
    except ValueError:
        pass

    # urlparse resolves userinfo (the part before @) correctly on its own,
    # but an @ appearing before the real host in the raw string is itself
    # the classic "make it LOOK like it points somewhere else" trick.
    authority = url.split('://', 1)[-1].split('/', 1)[0]
    if '@' in authority:
        flags.append("Contains an '@' before the host - a classic trick to disguise the real destination")

    if parsed.port and parsed.port not in (80, 443):
        flags.append(f"Uses a non-standard port ({parsed.port})")

    registrable = _registrable_domain(hostname) if hostname else ''
    is_shortener = hostname in URL_SHORTENER_DOMAINS

    if hostname and registrable and hostname != registrable and not is_ip_host:
        subdomain_labels = [l for l in hostname[:-len(registrable)].strip('.').split('.') if l]
        if len(subdomain_labels) >= 4:
            flags.append(f"Unusually deep subdomain nesting ({len(subdomain_labels)} levels before {registrable})")

    tld = registrable.rsplit('.', 1)[-1] if '.' in registrable else ''
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Uses a TLD ('.{tld}') that sees disproportionate phishing/malware abuse")

    if is_shortener:
        flags.append('This is a known URL-shortener - see the Redirect Chain check above for where it actually leads')

    if len(url) > 200:
        flags.append(f"Unusually long URL ({len(url)} characters)")

    return {
        'is_ip_host': is_ip_host,
        'is_shortener': is_shortener,
        'flags': flags,
    }


# --- Providers that reuse an already-configured hash-scanning key ----------

class VirusTotalURLAPI(VirusTotalAPI):
    """VirusTotal URL reputation, with the multi-vendor `categories` field
    used as the primary substitute for an authoritative Palo Alto/Symantec
    category (see the URL-scanning plan for why those aren't queryable via
    a public API)."""

    @staticmethod
    def _url_id(url: str) -> str:
        # VT v3 identifies URL objects by the base64 (no padding) of the URL itself.
        return base64.urlsafe_b64encode(url.encode()).decode().strip('=')

    async def query_url(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {'x-apikey': self.api_key}
        url_id = self._url_id(url)

        async with session.get(f"{self.base_url}/urls/{url_id}", headers=headers) as response:
            if response.status == 404:
                return await self._submit_and_wait(session, headers, url)
            elif response.status == 401:
                raise Exception("Invalid VT_API_KEY in config.env")
            elif response.status == 429:
                raise Exception("VirusTotal rate limit exceeded")
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")

            data = await response.json()
            return self._format(data, url)

    async def _submit_and_wait(self, session, headers, url: str) -> Dict[str, Any]:
        form = aiohttp.FormData()
        form.add_field('url', url)
        async with session.post(f"{self.base_url}/urls", headers=headers, data=form) as response:
            if response.status not in (200, 201):
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            analysis_id = (await response.json())['data']['id']

        status = None
        for _ in range(6):  # up to ~30s for a first-pass verdict on a brand-new URL
            await asyncio.sleep(5)
            async with session.get(f"{self.base_url}/analyses/{analysis_id}", headers=headers) as response:
                if response.status != 200:
                    continue
                analysis = await response.json()
                status = analysis['data']['attributes'].get('status')
            if status == 'completed':
                break

        async with session.get(f"{self.base_url}/urls/{self._url_id(url)}", headers=headers) as response:
            if response.status != 200:
                return {'not_found': True, 'context': 'Newly submitted - VirusTotal has not finished scanning it yet'}
            return self._format(await response.json(), url)

    def _format(self, data: Dict[str, Any], url: str) -> Dict[str, Any]:
        attr = data['data']['attributes']
        stats = attr.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
        total = sum(stats.values()) or 1

        result = {
            'malicious': malicious > 0,
            'detection_ratio': f"{malicious}/{total} engines",
            'report_link': f"https://www.virustotal.com/gui/url/{self._url_id(url)}",
            'final_url': attr.get('last_final_url') or url,
        }

        categories = attr.get('categories', {})  # {vendor_name: category}
        if categories:
            result['categories'] = categories
            values = list(categories.values())
            result['category'] = max(set(values), key=values.count)

        if malicious > 0:
            engines = attr.get('last_analysis_results', {})
            threats = [r['result'] for r in engines.values()
                       if r.get('category') in ('malicious', 'suspicious') and r.get('result')]
            if threats:
                result['signature'] = threats[0]

        return result


class MetaDefenderURLAPI(MetaDefenderAPI):
    """URL reputation + classification via MetaDefender Cloud. The lookup is
    a simple GET with the URL as a path parameter - encoding it isn't
    consistently documented, so this tries base64 first (matching
    VirusTotal's convention) and falls back to a plain URL-encoded path."""

    async def query_url(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {'apikey': self.api_key}

        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        data = await self._get(session, headers, encoded)
        if data is None:
            data = await self._get(session, headers, quote(url, safe=''))
        if data is None:
            return {'not_found': True}

        lookup = data.get('lookup_results', {})
        detected_by = lookup.get('detected_by', 0) or 0
        sources = lookup.get('sources', []) or []

        result = {
            'malicious': bool(detected_by),
            'detection_ratio': f"{detected_by}/{len(sources) or 1} sources",
            'report_link': f"https://metadefender.opswat.com/results/url/{encoded}",
        }
        category = data.get('category') or data.get('url_category')
        if category:
            result['category'] = category
        return result

    async def _get(self, session, headers, path_value: str):
        async with session.get(f"{self.base_url}/url/{path_value}", headers=headers) as response:
            if response.status == 401:
                raise Exception("Invalid METADEFENDER_API_KEY in config.env")
            elif response.status == 429:
                raise Exception("MetaDefender API rate limit exceeded")
            elif response.status in (400, 404):
                return None  # try the other encoding, or give up as not_found
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            return await response.json()


class OTXURLAPI(OTXAlienVaultAPI):
    """AlienVault OTX URL indicator - reports whether other analysts have
    linked the URL to a threat pulse."""

    async def query_url(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {'X-OTX-API-KEY': self.api_key}
        endpoint = f"{self.base_url}/indicators/url/{quote(url, safe='')}/general"

        async with session.get(endpoint, headers=headers) as response:
            if response.status == 404:
                return {'not_found': True}
            elif response.status == 401:
                raise Exception("Invalid OTX_API_KEY in config.env")
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            data = await response.json()

        pulse_info = data.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        if pulse_count == 0:
            return {'not_found': True}

        result = {
            'malicious': True,
            'context': f"Associated with {pulse_count} threat reports",
            'report_link': f"https://otx.alienvault.com/indicator/url/{quote(url, safe='')}",
        }
        pulses = pulse_info.get('pulses', [])
        if pulses:
            result['threat_name'] = pulses[0].get('name', 'Unknown')
        return result


class HybridAnalysisURLAPI(HybridAnalysisAPI):
    """Hybrid Analysis 'quick scan' of a URL (CrowdStrike ML static analysis
    + MetaDefender AV) - lighter weight than a full sandbox detonation."""

    async def query_url(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {'api-key': self.api_key, 'User-Agent': 'Falcon Sandbox'}
        form = aiohttp.FormData()
        form.add_field('url', url)
        form.add_field('scan_type', 'all')

        async with session.post(f"{self.base_url}/quick-scan/url", headers=headers, data=form) as response:
            if response.status == 401:
                raise Exception("Invalid HYBRID_API_KEY in config.env")
            elif response.status == 429:
                raise Exception("Rate limit exceeded.")
            elif response.status not in (200, 201):
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            data = await response.json()

        scan_id = data.get('id') or data.get('scan_id')
        if not data.get('finished', True) and scan_id:
            for _ in range(6):
                await asyncio.sleep(5)
                async with session.get(f"{self.base_url}/quick-scan/{scan_id}", headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('finished'):
                            break

        verdict = (data.get('verdict') or '').lower()
        result = {
            'malicious': verdict in ('malicious', 'suspicious'),
            'report_link': f"https://www.hybrid-analysis.com/quick-scan/{scan_id}" if scan_id else "https://www.hybrid-analysis.com/",
        }
        if verdict:
            result['signature'] = verdict.title()

        scanners = data.get('scanners_v2') or data.get('scanners') or {}
        if scanners:
            hits = sum(1 for s in scanners.values() if isinstance(s, dict) and s.get('status') == 'malicious')
            result['detection_ratio'] = f"{hits}/{len(scanners)} engines"
        return result


# NOTE: Triage is NOT offered as a URL-scanning provider (no TriageURLAPI
# here, unlike the other hash-scanning providers above). Submitting a URL
# for sandbox detonation ('kind: fetch') returned HTTP 401 on a working,
# already-configured key that submits files/hashes just fine - confirmed
# directly, not a guess - which points at a tier restriction on free/
# community Triage accounts rather than a bad key. Rather than show a
# permanently-broken error card on every URL lookup, it's left out
# entirely; Triage remains fully available for hash/file scanning
# (hash_lookup.py's TriageSandboxAPI, via the Sandbox Upload tab and
# Single Lookup for hashes), where it does work on the free tier.


# --- URL-only providers (need their own keys) -------------------------------

class URLhausAPI(BaseAPI):
    """abuse.ch URLhaus - known malware-distribution URL database. Reuses
    the same Auth-Key as MalwareBazaar/ThreatFox (config.env: MB_API_KEY)."""

    def __init__(self):
        super().__init__('MB_API_KEY')
        self.base_url = 'https://urlhaus-api.abuse.ch/v1/url/'

    async def query_url(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {'Auth-Key': self.api_key}

        async with session.post(self.base_url, headers=headers, data={'url': url}) as response:
            if response.status == 401:
                raise Exception("Invalid MB_API_KEY in config.env")
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            result_data = await response.json()

        if result_data.get('query_status') != 'ok':
            return {'not_found': True}

        result = {
            'malicious': True,
            'signature': result_data.get('threat', 'malware_download'),
            'context': f"Status: {result_data.get('url_status', 'unknown')}",
            'report_link': result_data.get('urlhaus_reference', 'https://urlhaus.abuse.ch/'),
        }
        tags = result_data.get('tags')
        if tags:
            result['threat_name'] = ', '.join(tags[:5])
        return result


# NOTE: Google Safe Browsing is deliberately NOT offered as a provider.
# The free v4 Lookup API is licensed for non-commercial use only - Google's
# terms require either a commercial agreement or the paid Web Risk API for
# any business/enterprise use, which this tool (built for a corporate
# security BU) is. Its marginal detection value was also small on top of
# what's already here: VirusTotal's 90+ engines already overlap heavily
# with Safe Browsing's own coverage, and OpenPhish/CheckPhish/
# IPQualityScore (phishing) plus URLhaus (malware URLs) already provide
# dedicated signal in the categories Safe Browsing would have added.


class OpenPhishAPI(BaseAPI):
    """OpenPhish's free community feed of currently-active phishing URLs.

    Used in place of PhishTank: PhishTank's checkurl API now sits behind a
    Cloudflare managed challenge (a JS/browser-fingerprint check) that a
    plain HTTP client can't pass - confirmed directly, every request comes
    back HTTP 403 with a challenge page instead of JSON, and there's no
    supported way around that short of running a real browser, which isn't
    a reasonable dependency for this app. OpenPhish's community feed needs
    no key/signup and isn't behind any such challenge, at the cost of being
    a smaller, less complete list than PhishTank's (or OpenPhish's own paid
    feed) - free for personal/testing use per OpenPhish's community feed
    terms. It's a flat list, not a per-URL query API, so this fetches (and
    briefly caches) the whole feed and checks membership locally."""

    FEED_URL = 'https://openphish.com/feed.txt'
    CACHE_TTL_SECONDS = 600  # the feed itself only refreshes every ~12h - no need to refetch often

    def __init__(self):
        super().__init__('')  # no key required
        self._cached_urls = None
        self._cached_at = 0.0

    def is_configured(self) -> bool:
        return True

    async def _fetch_feed(self, session: aiohttp.ClientSession) -> set:
        now = time.time()
        if self._cached_urls is not None and (now - self._cached_at) < self.CACHE_TTL_SECONDS:
            return self._cached_urls

        async with session.get(self.FEED_URL) as response:
            if response.status != 200:
                raise Exception(f"OpenPhish feed returned HTTP {response.status}")
            text = await response.text()

        self._cached_urls = {line.strip() for line in text.splitlines() if line.strip()}
        self._cached_at = now
        return self._cached_urls

    async def query_url(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        feed = await self._fetch_feed(session)

        stripped = {u.rstrip('/') for u in feed}
        match = url in feed or url.rstrip('/') in stripped

        if match:
            return {
                'malicious': True,
                'context': "Listed on OpenPhish's community feed of currently active phishing URLs",
                'report_link': 'https://openphish.com/phishing_targets.html',
            }
        return {
            'malicious': False,
            'context': f"Not found among {len(feed)} URLs on OpenPhish's current community feed",
        }


class IPQualityScoreAPI(BaseAPI):
    """Malicious URL Scanner API - ML-based phishing/malware/scam detection
    plus a `category` field used as a second substitute for the Palo
    Alto/Symantec category ask."""

    def __init__(self):
        super().__init__('IPQS_API_KEY')
        self.base_url = 'https://www.ipqualityscore.com/api/json/url'

    async def query_url(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        endpoint = f"{self.base_url}/{self.api_key}/{quote(url, safe='')}"

        async with session.get(endpoint) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            data = await response.json()

        if data.get('success') is False:
            raise Exception(data.get('message', 'IPQualityScore request failed'))

        malicious = bool(data.get('unsafe') or data.get('malware') or data.get('phishing') or data.get('spamming'))
        risk_score = data.get('risk_score')

        result = {'malicious': malicious}
        if risk_score is not None:
            result['context'] = f"Risk score: {risk_score}/100"
        if data.get('category'):
            result['category'] = data['category']
        flags = [f for f in ('phishing', 'malware', 'spamming', 'suspicious') if data.get(f)]
        if flags:
            result['threat_name'] = ', '.join(flags)
        result['report_link'] = 'https://www.ipqualityscore.com/threat-feeds/malicious-url-scanner'
        return result


class URLScanIOAPI(BaseAPI):
    """urlscan.io live browser-rendered scan - screenshot, redirect chain,
    and verdict tags. The screenshot is the single biggest analyst-UX win
    for the enterprise-whitelisting use case (see the URL-scanning plan)."""

    def __init__(self):
        super().__init__('URLSCAN_API_KEY')
        self.base_url = 'https://urlscan.io/api/v1'

    async def query_url(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {'API-Key': self.api_key, 'Content-Type': 'application/json'}

        async with session.post(f"{self.base_url}/scan/", headers=headers,
                                 json={'url': url, 'visibility': 'unlisted'}) as response:
            if response.status == 401:
                raise Exception("Invalid URLSCAN_API_KEY in config.env")
            elif response.status == 429:
                raise Exception("urlscan.io rate limit exceeded")
            elif response.status not in (200, 201):
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            submit_data = await response.json()

        result_api_url = submit_data.get('api')
        scan_uuid = submit_data.get('uuid')
        if not result_api_url:
            return {'not_found': True, 'context': 'Scan submitted but no result URL returned'}

        data = None
        for _ in range(12):  # urlscan scans typically finish in 10-20s; allow up to ~1 min
            await asyncio.sleep(5)
            async with session.get(result_api_url) as response:
                if response.status == 200:
                    data = await response.json()
                    break

        if data is None:
            return {
                'not_found': True,
                'report_link': submit_data.get('result'),
                'context': 'Scan still processing - check the report link shortly',
            }

        verdicts = data.get('verdicts', {})
        overall = verdicts.get('overall', {})
        page = data.get('page', {})
        task = data.get('task', {})

        result = {
            'malicious': bool(overall.get('malicious')),
            'report_link': task.get('reportURL') or submit_data.get('result'),
            'final_url': page.get('url'),
        }
        if scan_uuid:
            result['screenshot_url'] = f"https://urlscan.io/screenshots/{scan_uuid}.png"
        if overall.get('score') is not None:
            result['context'] = f"urlscan verdict score: {overall['score']}"
        tags = verdicts.get('urlscan', {}).get('tags')
        if tags:
            result['threat_name'] = ', '.join(tags[:5])
        return result


class CheckPhishAPI(BaseAPI):
    """CheckPhish (Bolster) - deep-learning visual phishing/scam detection
    (brand impersonation, tech-support scams, gift-card scams, ...)."""

    def __init__(self):
        super().__init__('CHECKPHISH_API_KEY')
        self.base_url = 'https://developers.checkphish.ai/api/neo/scan'

    async def query_url(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        async with session.post(self.base_url, json={
            'apiKey': self.api_key, 'urlInfo': {'url': url}, 'scanType': 'full'
        }) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            submit_data = await response.json()

        job_id = submit_data.get('jobID')
        if not job_id:
            raise Exception(submit_data.get('errorMessage', 'CheckPhish did not return a job id'))

        status_url = 'https://developers.checkphish.ai/api/neo/scan/status'
        data = None
        for _ in range(6):
            await asyncio.sleep(5)
            async with session.post(status_url, json={'apiKey': self.api_key, 'jobID': job_id, 'insights': True}) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('status') == 'DONE':
                        break

        if data is None or data.get('status') != 'DONE':
            return {'not_found': True, 'context': 'Scan still processing - check back shortly'}

        disposition = (data.get('disposition') or 'clean').lower()
        result = {
            'malicious': disposition in ('phish', 'suspicious'),
            'context': f"Disposition: {disposition}",
            'report_link': data.get('insights', 'https://checkphish.ai/'),
        }
        if data.get('brand'):
            result['threat_name'] = f"Impersonates: {data['brand']}"
        return result


# --- Certificate / legitimacy checks (no API key required) -----------------

class CertificateChecker:
    """Self-performed TLS handshake - runs for every URL lookup, unlike the
    (slower, rate-limited) SSL Labs deep-dive below which is opt-in only."""

    @staticmethod
    def check(hostname: str, port: int = 443, timeout: float = 6.0) -> Dict[str, Any]:
        try:
            # OS trust store (see _new_ssl_context in hash_lookup.py) - a
            # site whose chain relies on an intermediate only the OS store
            # has must not get reported as "untrusted" here just because a
            # certifi snapshot is missing it.
            ctx = _new_ssl_context() or ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
        except ssl.SSLCertVerificationError as e:
            # An untrusted/self-signed/hostname-mismatched cert is itself a
            # legitimacy signal - worth reporting, not just a failed lookup.
            return CertificateChecker._insecure_result(hostname, port, timeout, str(e))
        except Exception as e:
            return {'error': f"Could not establish TLS connection: {_exc_text(e)}"}

        return CertificateChecker._format(cert, cipher)

    @staticmethod
    def _insecure_result(hostname: str, port: int, timeout: float, verify_error: str) -> Dict[str, Any]:
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
        except Exception as e:
            return {'error': f"Could not establish TLS connection: {_exc_text(e)}"}

        formatted = CertificateChecker._format(cert, cipher)
        formatted['trusted'] = False
        formatted['warning'] = f"Certificate not trusted: {verify_error}"
        return formatted

    @staticmethod
    def _format(cert: dict, cipher) -> Dict[str, Any]:
        def _parse(dt_str):
            try:
                return datetime.strptime(dt_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            except Exception:
                return None

        not_before = _parse(cert.get('notBefore', ''))
        not_after = _parse(cert.get('notAfter', ''))
        now = datetime.now(timezone.utc)

        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))

        expired = bool(not_after and now > not_after)
        age_days = (now - not_before).days if not_before else None

        result = {
            'trusted': True,
            'subject_cn': subject.get('commonName', 'N/A'),
            'subject_org': subject.get('organizationName'),
            'issuer_cn': issuer.get('commonName', 'N/A'),
            'issuer_org': issuer.get('organizationName'),
            'not_before': not_before.strftime('%Y-%m-%d') if not_before else 'N/A',
            'not_after': not_after.strftime('%Y-%m-%d') if not_after else 'N/A',
            'expired': expired,
            'age_days': age_days,
            'cipher': cipher[0] if cipher else None,
        }
        if expired:
            result['warning'] = 'Certificate has expired'
        elif age_days is not None and age_days < 14:
            result['warning'] = (
                f'Certificate issued only {age_days} day(s) ago - common for freshly-stood-up phishing infrastructure'
            )
        return result


class CertTransparencyAPI:
    """Free, keyless Certificate Transparency history lookup - surfaces a
    domain's full certificate history (unusual issuers, lookalike
    subdomains, or no history at all for a brand-new site).

    Tries SSLMate's Certspotter API first, falling back to crt.sh only if
    Certspotter has nothing. crt.sh is the traditional/well-known choice,
    but it's a single volunteer-run service with no SLA that's frequently
    unreliable under load - verified directly: querying crt.sh for
    microsoft.com returned a bare 502, and a.com returned a 503, while
    Certspotter answered both instantly. crt.sh remains the fallback (and
    the human-facing report link, since it's the link analysts recognize)
    rather than being dropped entirely, since the two pull from overlapping
    but not identical sets of CT logs."""

    CERTSPOTTER_URL = 'https://api.certspotter.com/v1/issuances'
    CRTSH_URL = 'https://crt.sh/'

    def __init__(self):
        self.session = None

    def is_configured(self) -> bool:
        return True  # no key required, always available

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15),
                connector=aiohttp.TCPConnector(ssl=_new_ssl_context()),
            )
        return self.session

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def query(self, hostname: str) -> Dict[str, Any]:
        session = await self._get_session()

        result = await self._query_certspotter(session, hostname)
        if result is not None:
            return result

        return await self._query_crtsh(session, hostname)

    async def _query_certspotter(self, session: aiohttp.ClientSession, hostname: str):
        """Returns a result dict on success, or None to fall through to
        crt.sh (rate-limited, errored, or otherwise unavailable right now -
        never raises, since this is only the preferred path, not the only one)."""
        try:
            params = {'domain': hostname, 'include_subdomains': 'false', 'expand': 'issuer'}
            async with session.get(self.CERTSPOTTER_URL, params=params) as response:
                if response.status != 200:
                    return None
                entries = await response.json()
        except Exception:
            return None

        if not isinstance(entries, list):
            return None
        if not entries:
            return {
                'cert_count': 0,
                'context': 'No historical certificates found - domain may be brand new',
                'report_link': f'https://crt.sh/?q={quote(hostname)}',
            }

        issuers = sorted({(e.get('issuer') or {}).get('friendly_name') or 'Unknown' for e in entries})
        return {
            'cert_count': len(entries),
            'issuers': issuers[:5],
            'report_link': f'https://crt.sh/?q={quote(hostname)}',
        }

    async def _query_crtsh(self, session: aiohttp.ClientSession, hostname: str) -> Dict[str, Any]:
        try:
            async with session.get(self.CRTSH_URL, params={'q': hostname, 'output': 'json'}) as response:
                if response.status != 200:
                    return {'error': f"Both Certspotter and crt.sh are unavailable right now (crt.sh: HTTP {response.status})"}
                text = await response.text()
                entries = json.loads(text) if text.strip() else []
        except Exception as e:
            return {'error': f"Both Certspotter and crt.sh are unavailable right now (crt.sh: {_exc_text(e)})"}

        if not entries:
            return {'cert_count': 0, 'context': 'No historical certificates found - domain may be brand new'}

        issuers = sorted({e.get('issuer_name', 'Unknown') for e in entries})
        return {
            'cert_count': len(entries),
            'issuers': issuers[:5],
            'report_link': f'https://crt.sh/?q={quote(hostname)}',
        }


class SSLLabsAPI:
    """Optional deep-dive certificate/configuration grade via Qualys SSL
    Labs. Not run automatically for every lookup (see CertificateChecker) -
    a single fresh assessment takes ~1-2 minutes and is rate-limited, so
    this is only invoked on demand for one URL at a time (Phase 1 UI wires
    it to an explicit button, not the default results view)."""

    BASE_URL = 'https://api.ssllabs.com/api/v3/analyze'

    def __init__(self):
        self.session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=20),
                connector=aiohttp.TCPConnector(ssl=_new_ssl_context()),
            )
        return self.session

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def deep_scan(self, hostname: str, max_wait_seconds: int = 150) -> Dict[str, Any]:
        session = await self._get_session()
        params = {'host': hostname, 'fromCache': 'on', 'maxAge': '24', 'all': 'done'}

        data = {}
        elapsed = 0
        while elapsed <= max_wait_seconds:
            async with session.get(self.BASE_URL, params=params) as response:
                if response.status == 429:
                    raise Exception("SSL Labs rate limit exceeded - try again later")
                elif response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"HTTP {response.status}: {error_text}")
                data = await response.json()

            status = data.get('status')
            if status in ('READY', 'ERROR'):
                break
            params.pop('fromCache', None)  # only force a cached/fresh assessment on the first call
            await asyncio.sleep(10)
            elapsed += 10

        if data.get('status') == 'ERROR':
            raise Exception(data.get('statusMessage', 'SSL Labs assessment failed'))
        if data.get('status') != 'READY':
            return {'status': 'pending', 'context': 'Still assessing - check back in a minute'}

        endpoints = data.get('endpoints', [])
        grades = sorted({e.get('grade') for e in endpoints if e.get('grade')})
        return {
            'status': 'READY',
            'grade': grades[0] if grades else 'N/A',
            'endpoints': [{'ipAddress': e.get('ipAddress'), 'grade': e.get('grade')} for e in endpoints],
            'report_link': f'https://www.ssllabs.com/ssltest/analyze.html?d={quote(hostname)}',
        }


# --- Extra signals (no API key required) ------------------------------------

_MULTI_PART_TLD_SECOND_LEVEL = {'co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'gob', 'or'}


def _registrable_domain(hostname: str) -> str:
    """Best-effort registrable-domain extraction (last 2 labels, or last 3
    for common two-part TLDs like .co.uk/.com.au) without needing the full
    Public Suffix List - good enough for RDAP lookups and the brand-domain
    comparison below, not a substitute for a proper PSL-based parser."""
    labels = hostname.split('.')
    if len(labels) <= 2:
        return hostname
    if len(labels[-1]) == 2 and labels[-2] in _MULTI_PART_TLD_SECOND_LEVEL:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def _vcard_fn(vcard) -> Optional[str]:
    """Pull the 'fn' (full name) property out of an RDAP jCard array."""
    try:
        for entry in vcard[1]:
            if entry[0] == 'fn':
                return entry[3]
    except Exception:
        pass
    return None


class DomainAgeAPI:
    """Free, keyless domain-registration-age lookup via RDAP - the
    structured-JSON, IANA-bootstrapped successor to WHOIS. No API key, no
    third-party aggregator, no rate-limit story. A brand-new domain is a
    meaningful risk signal for both use cases: an enterprise-whitelisting
    candidate registered last week, or a download URL on a domain far
    younger than the vendor's real one."""

    BOOTSTRAP_URL = 'https://rdap.org/domain/'

    def __init__(self):
        self.session = None

    def is_configured(self) -> bool:
        return True

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=12),
                connector=aiohttp.TCPConnector(ssl=_new_ssl_context()),
            )
        return self.session

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def query(self, hostname: str) -> Dict[str, Any]:
        domain = _registrable_domain(hostname)
        session = await self._get_session()
        try:
            # Several registries' RDAP servers (Verisign's .com/.net RDAP
            # included) 403 requests with no/a bare Python User-Agent -
            # confirmed directly: identical request, 403 with none, 200
            # with a browser-style one.
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; SandBoxEQ/1.0)'}
            async with session.get(f"{self.BOOTSTRAP_URL}{domain}", headers=headers) as response:
                if response.status == 404:
                    return {'not_found': True, 'context': f'No RDAP record for {domain}'}
                if response.status != 200:
                    return {'error': f'RDAP lookup returned HTTP {response.status}'}
                data = await response.json()
        except Exception as e:
            return {'error': f'RDAP lookup failed: {_exc_text(e)}'}

        events = {e.get('eventAction'): e.get('eventDate') for e in data.get('events', []) if e.get('eventAction')}
        registered = events.get('registration')

        registrar = None
        for entity in data.get('entities', []):
            if 'registrar' in (entity.get('roles') or []):
                registrar = _vcard_fn(entity.get('vcardArray')) or entity.get('handle')
                break

        result = {'domain': domain}
        if registered:
            try:
                reg_dt = datetime.fromisoformat(registered.replace('Z', '+00:00'))
                age_days = (datetime.now(timezone.utc) - reg_dt).days
                result['registered_date'] = reg_dt.strftime('%Y-%m-%d')
                result['age_days'] = age_days
                if age_days < 30:
                    result['warning'] = f'Domain registered only {age_days} day(s) ago'
            except Exception:
                pass
        if registrar:
            result['registrar'] = registrar
        if not result.get('registered_date'):
            result['context'] = "Registration date not exposed by this domain's RDAP record"
        return result


class RedirectChainChecker:
    """Follows HTTP redirects one hop at a time (rather than aiohttp's
    built-in allow_redirects, which discards the intermediate hops) to
    surface the full chain - flags when a URL routes through a different
    domain before landing, a common pattern for trojanized-installer
    distribution and shortener-based phishing."""

    MAX_HOPS = 8

    def __init__(self):
        self.session = None

    def is_configured(self) -> bool:
        return True

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15),
                connector=aiohttp.TCPConnector(ssl=_new_ssl_context()),
            )
        return self.session

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def _fetch_once(self, session: aiohttp.ClientSession, url: str):
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SandBoxEQ/1.0)'}
        async with session.head(url, headers=headers, allow_redirects=False) as response:
            if response.status == 405:  # some servers reject HEAD - fall back to GET
                async with session.get(url, headers=headers, allow_redirects=False) as response2:
                    return response2.status, response2.headers.get('Location')
            return response.status, response.headers.get('Location')

    async def trace(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        chain = [url]
        current = url
        try:
            for _ in range(self.MAX_HOPS):
                status, location = await self._fetch_once(session, current)
                if status not in (301, 302, 303, 307, 308) or not location:
                    break
                current = urljoin(current, location)
                chain.append(current)
        except Exception as e:
            return {'chain': chain, 'hops': len(chain) - 1, 'error': f'Redirect trace stopped early: {_exc_text(e)}'}

        result = {'chain': chain, 'hops': len(chain) - 1, 'final_url': chain[-1]}
        start_host, end_host = urlparse(chain[0]).hostname, urlparse(chain[-1]).hostname
        if start_host and end_host and start_host != end_host:
            result['warning'] = f'Redirects to a different domain: {start_host} -> {end_host}'
        return result


# A small, deliberately short list of high-value/commonly-impersonated
# brands - not meant to be exhaustive, just a fast heuristic layer on top
# of the reputation engines above, which only catch a lookalike domain
# once someone else has already seen and reported it.
KNOWN_BRAND_DOMAINS = [
    'microsoft.com', 'office.com', 'live.com', 'outlook.com', 'azure.com',
    'google.com', 'gmail.com',
    'apple.com', 'icloud.com',
    'amazon.com',
    'okta.com', 'onelogin.com',
    'paypal.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
    'adobe.com', 'dropbox.com', 'salesforce.com', 'slack.com', 'zoom.us',
    'github.com', 'gitlab.com', 'cloudflare.com',
    'facebook.com', 'linkedin.com', 'twitter.com', 'x.com', 'instagram.com',
]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def check_typosquat(hostname: str) -> Dict[str, Any]:
    """Flags a domain suspiciously close to (but not exactly) a known
    brand domain - a classic lookalike/phishing signal that a reputation
    engine won't catch until someone else has already reported the
    domain. Synchronous/instant - no network call."""
    registrable = _registrable_domain(hostname)
    if registrable in KNOWN_BRAND_DOMAINS:
        return {'is_known_brand': True, 'domain': registrable}

    closest, closest_distance = None, 999
    for brand in KNOWN_BRAND_DOMAINS:
        if abs(len(registrable) - len(brand)) > 3:
            continue  # too different in length for the edit distance to mean much
        d = _levenshtein(registrable, brand)
        if d < closest_distance:
            closest, closest_distance = brand, d

    if closest and 0 < closest_distance <= 2:
        return {
            'is_known_brand': False,
            'domain': registrable,
            'closest_brand': closest,
            'warning': f"Looks similar to '{closest}' (edit distance {closest_distance}) but is NOT that domain - possible lookalike/typosquat",
        }
    return {'is_known_brand': False, 'domain': registrable, 'context': 'No close match to a known brand domain'}


class FaviconChecker:
    """Confirms/strengthens a typosquat suspicion with hard evidence: many
    phishing kits clone the real site's favicon wholesale onto a lookalike
    domain, since it's the fastest way to make a fake login page look
    convincing. Fetches the target's favicon and, when check_typosquat()
    already nominated a close brand match, that brand's real favicon too
    (cached after first fetch - brand favicons rarely change) - an exact
    byte-for-byte hash match on a domain that ISN'T the real brand is about
    as strong a phishing signal as this tool can produce without a paid
    feed."""

    _brand_favicon_cache: Dict[str, Optional[str]] = {}  # class-level: shared across instances/requests

    def __init__(self):
        self.session = None

    def is_configured(self) -> bool:
        return True

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
                connector=aiohttp.TCPConnector(ssl=_new_ssl_context()),
            )
        return self.session

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def _fetch_favicon_hash(self, session: aiohttp.ClientSession, hostname: str) -> Optional[str]:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SandBoxEQ/1.0)'}
        for scheme in ('https', 'http'):
            try:
                async with session.get(f"{scheme}://{hostname}/favicon.ico", headers=headers) as response:
                    if response.status == 200:
                        data = await response.read()
                        if len(data) > 32:  # skip empty/placeholder responses
                            return hashlib.sha256(data).hexdigest()
            except Exception:
                continue
        return None

    async def check(self, hostname: str, typosquat: Dict[str, Any]) -> Dict[str, Any]:
        session = await self._get_session()
        target_hash = await self._fetch_favicon_hash(session, hostname)
        if target_hash is None:
            return {'context': 'No favicon found at this domain'}

        result = {'favicon_sha256': target_hash[:16]}  # short form, just for display/comparison-by-eye

        closest_brand = (typosquat or {}).get('closest_brand')
        if not closest_brand:
            return result

        if closest_brand not in self._brand_favicon_cache:
            self._brand_favicon_cache[closest_brand] = await self._fetch_favicon_hash(session, closest_brand)
        brand_hash = self._brand_favicon_cache[closest_brand]

        if brand_hash and brand_hash == target_hash:
            result['matches_brand'] = closest_brand
            result['warning'] = (
                f"This domain's favicon is byte-for-byte identical to {closest_brand}'s - strong evidence of a "
                f"cloned phishing kit, not just a coincidentally similar name"
            )
        return result


# Expected Content-Type prefixes per extension - deliberately loose
# (includes 'application/octet-stream', the generic fallback many servers
# use for any binary) since the goal is only to catch the obviously wrong
# case (an HTML error/gate page), not to strictly validate MIME types.
EXPECTED_CONTENT_TYPES = {
    '.exe': ('application/x-msdownload', 'application/octet-stream', 'application/vnd.microsoft.portable-executable', 'application/x-dosexec'),
    '.msi': ('application/x-msi', 'application/octet-stream'),
    '.zip': ('application/zip', 'application/x-zip-compressed', 'application/octet-stream'),
    '.dmg': ('application/x-apple-diskimage', 'application/octet-stream'),
    '.pkg': ('application/octet-stream', 'application/x-newton-compatible-pkg'),
    '.7z': ('application/x-7z-compressed', 'application/octet-stream'),
    '.rar': ('application/x-rar-compressed', 'application/vnd.rar', 'application/octet-stream'),
    '.deb': ('application/x-debian-package', 'application/vnd.debian.binary-package', 'application/octet-stream'),
    '.rpm': ('application/x-rpm', 'application/x-redhat-package-manager', 'application/octet-stream'),
    '.apk': ('application/vnd.android.package-archive', 'application/octet-stream'),
    '.iso': ('application/x-iso9660-image', 'application/octet-stream'),
    '.jar': ('application/java-archive', 'application/octet-stream'),
}


class DownloadContentChecker:
    """For a URL whose path looks like a direct file download: a HEAD
    request confirming the server actually serves something matching the
    expected file type. A URL ending in .exe that serves text/html back is
    very often an error/gate page (dead link, geo-block, auth wall, a
    since-pulled release) rather than the real installer - useful signal
    either way, and it's a single lightweight request."""

    def __init__(self):
        self.session = None

    def is_configured(self) -> bool:
        return True

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
                connector=aiohttp.TCPConnector(ssl=_new_ssl_context()),
            )
        return self.session

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def check(self, url: str) -> Optional[Dict[str, Any]]:
        path = urlparse(url).path.lower()
        ext = next((e for e in DOWNLOAD_FILE_EXTENSIONS if path.endswith(e)), None)
        if not ext:
            return None  # doesn't look like a file-download URL - nothing to check

        session = await self._get_session()
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SandBoxEQ/1.0)'}
        try:
            async with session.head(url, headers=headers, allow_redirects=True) as response:
                content_type = (response.headers.get('Content-Type') or '').split(';')[0].strip().lower()
                content_length = response.headers.get('Content-Length')
        except Exception as e:
            return {'expected_extension': ext, 'error': f'Could not check: {_exc_text(e)}'}

        result = {'expected_extension': ext, 'content_type': content_type or 'unknown'}
        if content_length and content_length.isdigit():
            result['content_length_bytes'] = int(content_length)

        expected = EXPECTED_CONTENT_TYPES.get(ext, ())
        if content_type and expected and content_type not in expected:
            if content_type.startswith('text/html'):
                result['warning'] = f"URL ends in {ext} but the server returned HTML, not a file - likely an error/gate page, not the real download"
            else:
                result['warning'] = f"URL ends in {ext} but the server returned Content-Type '{content_type}', which doesn't match"
        return result


class HostingReputationAPI(BaseAPI):
    """Resolves the domain's IP and checks it against AbuseIPDB - a signal
    independent of anything about the domain/URL itself: many phishing and
    malware operations reuse the same abused ("bulletproof") hosting over
    and over, so infrastructure-level reputation catches campaigns that
    haven't been reported under this particular domain yet."""

    def __init__(self):
        super().__init__('ABUSEIPDB_API_KEY')
        self.base_url = 'https://api.abuseipdb.com/api/v2/check'

    async def check(self, hostname: str) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            addr_infos = await loop.getaddrinfo(hostname, None)
            ip = addr_infos[0][4][0]
        except Exception as e:
            return {'error': f'Could not resolve {hostname}: {_exc_text(e)}'}

        session = await self._get_session()
        headers = {'Key': self.api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        try:
            async with session.get(self.base_url, headers=headers, params=params) as response:
                if response.status == 401:
                    raise Exception("Invalid ABUSEIPDB_API_KEY in config.env")
                elif response.status == 429:
                    raise Exception("AbuseIPDB rate limit exceeded")
                elif response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"HTTP {response.status}: {error_text}")
                payload = await response.json()
        except Exception as e:
            return {'ip': ip, 'error': _exc_text(e)}

        data = payload.get('data', {})
        score = data.get('abuseConfidenceScore') or 0
        result = {
            'ip': ip,
            'abuse_score': score,
            'country': data.get('countryCode'),
            'isp': data.get('isp'),
            'total_reports': data.get('totalReports', 0),
            'hosting_domain': data.get('domain'),
        }
        if score >= 50:
            result['warning'] = f"Hosting IP has a {score}% abuse-confidence score on AbuseIPDB ({data.get('totalReports', 0)} reports in the last 90 days)"
        return result


PER_PROVIDER_TIMEOUT_SECONDS = 110  # generous - covers Triage's ~90s detonation poll
OVERALL_TIMEOUT_SECONDS = 130  # hard ceiling on the whole lookup, independent of any single provider


async def _bounded(coro, timeout: float, timeout_message: str) -> Dict[str, Any]:
    """Runs `coro` with a hard wall-clock ceiling. Every provider call and
    the certificate/CT checks go through this - a single misbehaving
    provider (slow DNS, a backend that never answers, ...) must never hang
    the whole lookup, since nothing upstream of this function has its own
    timeout otherwise. Note: cancelling an asyncio.wait_for on a coroutine
    that's blocked inside a synchronous call in a thread executor (e.g.
    CertificateChecker.check on a stalled DNS lookup) stops the *await* but
    the underlying OS thread can keep running until the OS itself gives up -
    this bounds what the user waits on, not the thread's lifetime."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        return {'error': timeout_message}


async def cross_check_url_and_hash(url: str, file_hash: str, vt_api: Optional[VirusTotalURLAPI] = None) -> Dict[str, Any]:
    """Use case B (download-source validation): checks VirusTotal's 'files
    downloaded from this URL' relationship against a hash the user
    separately obtained. Works in both directions - called from a URL
    lookup with a supplied hash (Advanced Options' "Hash to cross-check"),
    or from a hash lookup with a supplied URL ("Download URL to
    cross-check") - it's the same underlying VT relationship either way.

    `vt_api` lets a caller that already has a configured+open
    VirusTotalURLAPI (URLLookupTool.lookup_url) reuse its session instead
    of opening a new one; a caller with no existing instance (the hash-side
    route) gets one created and closed here."""
    file_hash = strip_hash_label(file_hash).lower()
    owns_api = vt_api is None
    vt = vt_api or VirusTotalURLAPI()

    try:
        if not vt.is_configured():
            return {'hash': file_hash, 'match': None, 'note': 'VirusTotal not configured - cannot cross-check'}

        try:
            session = await vt._get_session()
            headers = {'x-apikey': vt.api_key}
            url_id = VirusTotalURLAPI._url_id(url)
            endpoint = f"{vt.base_url}/urls/{url_id}/downloaded_files"
            async with session.get(endpoint, headers=headers) as response:
                if response.status != 200:
                    return {'hash': file_hash, 'match': None,
                            'note': 'No downloaded-file relationship data available for this URL yet'}
                data = await response.json()
        except Exception as e:
            return {'hash': file_hash, 'match': None, 'note': f'Cross-check failed: {_exc_text(e)}'}

        seen_hashes = {item['id'].lower() for item in data.get('data', []) if item.get('id')}
        match = file_hash in seen_hashes
        if match:
            note = 'Matched a file VirusTotal has observed being downloaded from this URL'
        elif seen_hashes:
            note = 'This hash was NOT among the files VirusTotal has observed downloaded from this URL'
        else:
            note = 'VirusTotal has no recorded downloads from this URL to compare against'

        return {'hash': file_hash, 'url': url, 'match': match, 'seen_file_count': len(seen_hashes), 'note': note}
    finally:
        if owns_api:
            await vt.close_session()


class URLLookupTool:
    """Mirrors HashLookupTool (hash_lookup.py): fans a URL out concurrently
    to every configured URL-scanning provider, plus the always-on
    certificate/CT/domain-age/redirect/typosquat checks that don't need an
    API key."""

    def __init__(self, log_sink=None):
        load_dotenv(config_store.get_config_path())
        self.log_sink = log_sink
        self.apis = {
            'virustotal': VirusTotalURLAPI(),
            'metadefender': MetaDefenderURLAPI(),
            'otx': OTXURLAPI(),
            'urlhaus': URLhausAPI(),
            'hybrid_analysis': HybridAnalysisURLAPI(),
            'openphish': OpenPhishAPI(),
            'ipqualityscore': IPQualityScoreAPI(),
            'urlscan': URLScanIOAPI(),
            'checkphish': CheckPhishAPI(),
        }
        self.cert_transparency_api = CertTransparencyAPI()
        self.domain_age_api = DomainAgeAPI()
        self.redirect_checker = RedirectChainChecker()
        self.favicon_checker = FaviconChecker()
        self.download_content_checker = DownloadContentChecker()
        self.hosting_reputation_api = HostingReputationAPI()

    async def lookup_url(self, url: str, cross_check_hash: str = "") -> Dict[str, Any]:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc

        names = [name for name, api in self.apis.items() if api.is_configured()]
        tasks = [
            _bounded(
                self._query_api(name, self.apis[name], url),
                PER_PROVIDER_TIMEOUT_SECONDS,
                f"Timed out after {PER_PROVIDER_TIMEOUT_SECONDS}s waiting on this provider",
            )
            for name in names
        ]

        # Synchronous/instant, no network call - computed up front (rather
        # than after the gather, like typosquat used to be) since
        # FaviconChecker needs typosquat's closest_brand match to decide
        # whether there's a real-brand favicon worth comparing against.
        typosquat_result = check_typosquat(hostname) if hostname else None
        url_heuristics_result = check_url_heuristics(url)
        idn_result = check_idn_homoglyph(hostname) if hostname else None

        loop = asyncio.get_event_loop()
        # (extra_key, task) pairs for the keyless/extra checks - built as a
        # list rather than named variables so adding another one later is a
        # one-line change, not a repeat of the offset-tracking below.
        extras = []
        if hostname:
            extras.append(('certificate', _bounded(
                loop.run_in_executor(None, CertificateChecker.check, hostname),
                20, "Timed out establishing a TLS connection",
            )))
            extras.append(('cert_transparency', _bounded(
                self.cert_transparency_api.query(hostname),
                20, "Timed out querying Certspotter/crt.sh",
            )))
            extras.append(('domain_age', _bounded(
                self.domain_age_api.query(hostname),
                15, "Timed out querying RDAP",
            )))
            extras.append(('redirect_chain', _bounded(
                self.redirect_checker.trace(url),
                20, "Timed out tracing redirects",
            )))
            extras.append(('favicon', _bounded(
                self.favicon_checker.check(hostname, typosquat_result),
                15, "Timed out fetching favicon",
            )))
            extras.append(('download_content', _bounded(
                self.download_content_checker.check(url),
                15, "Timed out checking download Content-Type",
            )))
            if self.hosting_reputation_api.is_configured():
                extras.append(('hosting_reputation', _bounded(
                    self.hosting_reputation_api.check(hostname),
                    15, "Timed out querying AbuseIPDB",
                )))

        gather_targets = list(tasks) + [t for _, t in extras]

        try:
            # Per-task timeouts above should always fire first - this is a
            # pure safety net so the request can never hang past
            # OVERALL_TIMEOUT_SECONDS no matter what (this is exactly the
            # protection that was missing when this hung indefinitely).
            results_list = await asyncio.wait_for(
                asyncio.gather(*gather_targets, return_exceptions=True),
                timeout=OVERALL_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            results_list = [Exception(f"Lookup timed out after {OVERALL_TIMEOUT_SECONDS}s") for _ in gather_targets]

        api_results = {}
        for i, name in enumerate(names):
            result = results_list[i]
            api_results[name] = {'error': str(result)} if isinstance(result, Exception) else result

        for i, (key, _) in enumerate(extras, start=len(names)):
            result = results_list[i]
            if isinstance(result, Exception):
                api_results[key] = {'error': str(result)}
            elif result is not None:  # download_content returns None for a non-file-looking URL
                api_results[key] = result

        if typosquat_result is not None:
            api_results['typosquat'] = typosquat_result
        if idn_result is not None and idn_result.get('is_idn'):
            api_results['idn_check'] = idn_result
        if url_heuristics_result['flags'] or url_heuristics_result['is_shortener']:
            api_results['url_heuristics'] = url_heuristics_result

        if cross_check_hash.strip():
            api_results['cross_check'] = await _bounded(
                cross_check_url_and_hash(url, cross_check_hash, vt_api=self.apis.get('virustotal')),
                30, "Cross-check timed out",
            )

        # Only the keyless "extra check" sessions are closed here - the
        # provider (self.apis) sessions are deliberately left open for the
        # caller to close via close_all() once it's done with this tool
        # instance, since BulkProcessor reuses one URLLookupTool across many
        # lookup_url() calls and closing those mid-batch would force a new
        # TCP connection per provider per item instead of reusing one.
        await self.cert_transparency_api.close_session()
        await self.domain_age_api.close_session()
        await self.redirect_checker.close_session()
        await self.favicon_checker.close_session()
        await self.download_content_checker.close_session()
        await self.hosting_reputation_api.close_session()
        return api_results

    async def _query_api(self, api_name: str, api_instance, url: str) -> Dict[str, Any]:
        try:
            result = await api_instance.query_url(url)
        except Exception as e:
            error_text = _exc_text(e)
            if self.log_sink is not None:
                service_name = api_name.replace('_', ' ').title()
                self.log_sink(api_name, service_name, f"{service_name.upper()}\n{'-' * 40}\nError: {error_text}")
            return {'error': error_text}

        if self.log_sink is not None and not result.get('not_found'):
            service_name = api_name.replace('_', ' ').title()
            self.log_sink(api_name, service_name, build_log_text(service_name, api_name, result))
        return result


async def close_all(tool: 'URLLookupTool') -> None:
    """Convenience helper mirroring the `for api in lookup_tool.apis.values():
    await api.close_session()` pattern used throughout app.py."""
    for api in tool.apis.values():
        await api.close_session()
    await tool.cert_transparency_api.close_session()
    await tool.domain_age_api.close_session()
    await tool.redirect_checker.close_session()
    await tool.favicon_checker.close_session()
    await tool.download_content_checker.close_session()
    await tool.hosting_reputation_api.close_session()
