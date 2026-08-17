#!/usr/bin/env python3
"""
IP address lookup - mirrors hash_lookup.py/url_lookup.py's provider/plugin
pattern (BaseAPI, one class per provider, fanned out concurrently) but for
raw IP addresses instead of file hashes or URLs. Deliberately small: only 4
providers, no bespoke per-provider Jinja cards needed (the generic
label/color/link card loop in _results.html covers all of them), unlike the
much larger hash/url provider surface.
"""

import asyncio
import ipaddress
from typing import Any, Callable, Dict, Optional

import aiohttp

from hash_lookup import VirusTotalAPI, _exc_text, _new_ssl_context
from url_lookup import (
    HostingReputationAPI, PER_PROVIDER_TIMEOUT_SECONDS, OVERALL_TIMEOUT_SECONDS,
    _bounded, _vcard_fn,
)
import config_store
from dotenv import load_dotenv


def _is_valid_ip(value: str) -> bool:
    """True for a well-formed IPv4 or IPv6 address (not a CIDR range)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_ip(value: str) -> str:
    """Canonical string form (handles things like IPv4 leading zeros or
    IPv6 compression inconsistently typed) - only call after _is_valid_ip."""
    return str(ipaddress.ip_address(value))


# --- Providers that reuse an already-configured key -------------------------

class VirusTotalIPAPI(VirusTotalAPI):
    """VirusTotal's IP reputation report - same VT_API_KEY already used for
    hash and URL lookups, no separate configuration needed."""

    async def query_ip(self, ip: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {'x-apikey': self.api_key}

        async with session.get(f"{self.base_url}/ip_addresses/{ip}", headers=headers) as response:
            if response.status == 404:
                return {'not_found': True}
            elif response.status == 401:
                raise Exception("Invalid VT_API_KEY in config.env")
            elif response.status == 429:
                raise Exception("VirusTotal rate limit exceeded")
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            data = await response.json()

        attr = data['data']['attributes']
        stats = attr.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
        total = sum(stats.values()) or 1

        result = {
            'malicious': malicious > 0,
            'detection_ratio': f"{malicious}/{total} engines",
            'report_link': f"https://www.virustotal.com/gui/ip-address/{ip}",
        }
        if attr.get('country'):
            result['country'] = attr['country']
        if attr.get('as_owner'):
            result['context'] = f"AS{attr.get('asn', '?')} - {attr['as_owner']}"

        if malicious > 0:
            engines = attr.get('last_analysis_results', {})
            threats = sorted({r['result'] for r in engines.values()
                               if r.get('category') in ('malicious', 'suspicious') and r.get('result')})
            if threats:
                result['threat_name'] = ', '.join(threats[:3])
        return result


# --- Free, keyless checks ----------------------------------------------------

class IPWhoisAPI:
    """Free, keyless network/ASN WHOIS via RDAP - the same rdap.org
    bootstrap service url_lookup.py's DomainAgeAPI uses for domain WHOIS,
    just the /ip/ endpoint (network allocation) instead of /domain/."""

    BOOTSTRAP_URL = 'https://rdap.org/ip/'

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

    async def query(self, ip: str) -> Dict[str, Any]:
        session = await self._get_session()
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; SandBoxEQ/1.0)'}
            async with session.get(f"{self.BOOTSTRAP_URL}{ip}", headers=headers) as response:
                if response.status == 404:
                    return {'not_found': True, 'context': f'No RDAP record for {ip}'}
                if response.status != 200:
                    return {'error': f'RDAP lookup returned HTTP {response.status}'}
                data = await response.json()
        except Exception as e:
            return {'error': f'RDAP lookup failed: {_exc_text(e)}'}

        # Registrant/administrative contact details are essentially always
        # redacted for privacy, same as domain WHOIS - the organization name
        # is usually the only reachable field here.
        org = None
        for entity in data.get('entities', []):
            roles = entity.get('roles') or []
            if 'registrant' in roles or 'administrative' in roles:
                org = _vcard_fn(entity.get('vcardArray')) or entity.get('handle')
                if org:
                    break

        result: Dict[str, Any] = {}
        if data.get('name'):
            result['network_name'] = data['name']
        if data.get('startAddress') and data.get('endAddress'):
            result['range'] = f"{data['startAddress']} - {data['endAddress']}"
        if data.get('type'):
            result['allocation_type'] = data['type']
        if data.get('country'):
            result['country'] = data['country']
        if org:
            result['organization'] = org
        if data.get('handle'):
            result['handle'] = data['handle']
        if not result:
            result['context'] = 'No usable fields in this RDAP record'
        return result


class GeolocationAPI:
    """Free, keyless IP geolocation + reverse DNS via ip-api.com (45
    req/min on the free tier - plenty for interactive single lookups).
    Free tier is HTTP-only (no HTTPS) - fine here since this is a
    server-to-server call, not something a browser ever sees directly."""

    FIELDS = 'status,message,country,regionName,city,isp,org,as,reverse,query'

    def __init__(self):
        self.session = None

    def is_configured(self) -> bool:
        return True

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
        return self.session

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def query(self, ip: str) -> Dict[str, Any]:
        session = await self._get_session()
        try:
            async with session.get(f"http://ip-api.com/json/{ip}?fields={self.FIELDS}") as response:
                if response.status != 200:
                    return {'error': f'ip-api.com returned HTTP {response.status}'}
                data = await response.json()
        except Exception as e:
            return {'error': f'Geolocation lookup failed: {_exc_text(e)}'}

        # status == 'fail' covers private/reserved ranges (RFC1918, etc.) as
        # well as genuine lookup failures - message explains which.
        if data.get('status') != 'success':
            return {'not_found': True, 'context': data.get('message', 'No geolocation data available')}

        result = {
            'country': data.get('country'),
            'region': data.get('regionName'),
            'city': data.get('city'),
            'isp': data.get('isp'),
            'org': data.get('org'),
            'asn': data.get('as'),
        }
        if data.get('reverse'):
            result['reverse_dns'] = data['reverse']
        return result


def _log_line(key: str, result: Any) -> str:
    """Plain-text Terminal-tab line for one provider's IP-lookup result - a
    generic key:value dump rather than hash_lookup.py's build_log_text
    (which expects hash/URL-shaped fields like 'malicious'/'detection_ratio'
    that don't line up with WHOIS/geolocation's own field names - reusing it
    here would just print 'Clean/No threat detected' for every informational
    card regardless of what it actually found)."""
    label = key.replace('_', ' ').title()
    lines = [label.upper(), '-' * 40]
    if not isinstance(result, dict):
        lines.append(str(result))
        return "\n".join(lines)
    if result.get('error'):
        lines.append(f"Error: {result['error']}")
        return "\n".join(lines)
    if result.get('not_found'):
        lines.append(f"Not found: {result.get('context', '')}")
        return "\n".join(lines)
    for field, value in result.items():
        if field == 'report_link' or value in (None, '', []):
            continue
        lines.append(f"{field.replace('_', ' ').title()}: {value}")
    if result.get('report_link'):
        lines.append(f"Report: {result['report_link']}")
    return "\n".join(lines)


class IPLookupTool:
    """Mirrors HashLookupTool/URLLookupTool: fans an IP out concurrently to
    every configured provider, streaming each result back via on_result as
    it resolves - see url_lookup.py's lookup_url for the pattern this
    copies (_set/_track/_bounded)."""

    def __init__(self, log_sink=None):
        load_dotenv(config_store.get_config_path())
        self.log_sink = log_sink
        # Reuses url_lookup.py's HostingReputationAPI (same ABUSEIPDB_API_KEY
        # a user may already have configured for the URL lookup's "hosting
        # reputation" extra) rather than a second, separately-configured
        # AbuseIPDB client.
        self.abuseipdb_api = HostingReputationAPI()
        self.apis = {
            'virustotal': VirusTotalIPAPI(),
            'abuseipdb': self.abuseipdb_api,
            'ip_whois': IPWhoisAPI(),
            'geolocation': GeolocationAPI(),
        }

    async def lookup_ip(self, ip: str,
                         on_result: Optional[Callable[[str, Any], None]] = None) -> Dict[str, Any]:
        api_results: Dict[str, Any] = {}

        def _set(key: str, value: Any) -> None:
            if value is not None:
                api_results[key] = value
            if on_result is not None:
                on_result(key, value)

        async def _track(key: str, coro) -> None:
            try:
                result = await coro
            except Exception as e:
                result = {'error': str(e)}
            _set(key, result)
            if self.log_sink is not None:
                self.log_sink(key, key.replace('_', ' ').title(), _log_line(key, result))

        # Each provider class exposes its query under a different method
        # name (established by its own class's conventions) - just 4 of
        # them, so a small explicit mapping is clearer than forcing a
        # uniform interface onto classes with existing call sites elsewhere.
        provider_calls = {
            'virustotal': lambda: self.apis['virustotal'].query_ip(ip),
            'abuseipdb': lambda: self.abuseipdb_api.check_ip(ip),
            'ip_whois': lambda: self.apis['ip_whois'].query(ip),
            'geolocation': lambda: self.apis['geolocation'].query(ip),
        }

        gather_targets = []
        for key, make_coro in provider_calls.items():
            api = self.apis[key]
            if not api.is_configured():
                continue
            gather_targets.append(_track(key, _bounded(
                make_coro(),
                PER_PROVIDER_TIMEOUT_SECONDS,
                f"Timed out after {PER_PROVIDER_TIMEOUT_SECONDS}s waiting on this provider",
            )))

        try:
            await asyncio.wait_for(
                asyncio.gather(*gather_targets, return_exceptions=True),
                timeout=OVERALL_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            pass

        return api_results

    async def close_all(self) -> None:
        for api in self.apis.values():
            await api.close_session()
