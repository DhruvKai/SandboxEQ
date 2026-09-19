"""Offline IOC helpers: refang / defang and indicator extraction from free text.

No network calls, no third-party dependencies - pure regex + the stdlib
`ipaddress` module, same spirit as url_lookup.py's offline URL Structure /
IDN checks. Used by app.py's /api/ioc/extract route (Tools tab) and by
/lookup, which refangs whatever was pasted into the main search box so
`hxxps://evil[.]com` or `8[.]8[.]8[.]8` just works.
"""

import ipaddress
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit


# --- Refang -----------------------------------------------------------------

_OPEN = r'[\[\(\{]'
_CLOSE = r'[\]\)\}]'

# Ordered - the "://" form must run before the bare ":" form.
_REFANG_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'\bh(?:xx|xt|\*\*)p(s?)(?![A-Za-z0-9_])', re.I), r'http\1'),
    (re.compile(r'\bfxp(?![A-Za-z0-9_])', re.I), 'ftp'),
    (re.compile(rf'\s*{_OPEN}\s*://\s*{_CLOSE}\s*'), '://'),
    (re.compile(rf'{_OPEN}\s*:\s*{_CLOSE}'), ':'),
    (re.compile(rf'{_OPEN}\s*/\s*{_CLOSE}'), '/'),
    (re.compile(rf'\s*{_OPEN}\s*(?:\.|dot)\s*{_CLOSE}\s*', re.I), '.'),
    (re.compile(rf'\s*{_OPEN}\s*(?:@|at)\s*{_CLOSE}\s*', re.I), '@'),
    (re.compile(r'\\\.'), '.'),
]


def refang(text: str) -> str:
    """Undo the usual defanging conventions: hxxp/hXXp/h**p, [.] (.) {.} [dot],
    [://] [:] [/], [@] [at], and backslash-escaped dots. A no-op on text that
    was never defanged."""
    for pattern, replacement in _REFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


# --- Defang -----------------------------------------------------------------

_URL_PARTS_RE = re.compile(r'^([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)(.*)$', re.S)
_SCHEME_DEFANG = {'http': 'hxxp', 'https': 'hxxps', 'ftp': 'fxp'}


def defang_indicator(value: str, kind: str) -> str:
    """Defang one already-extracted indicator. Only the parts a mail client or
    browser would turn into a live link are touched (scheme, host dots,
    the @) - the URL path is left readable, matching common analyst practice."""
    if kind == 'urls':
        m = _URL_PARTS_RE.match(value)
        if not m:
            return value.replace('.', '[.]')
        scheme, authority, rest = m.groups()
        scheme = _SCHEME_DEFANG.get(scheme.lower(), scheme)
        return f"{scheme}[://]{authority.replace('.', '[.]')}{rest}"
    if kind in ('ipv4', 'domains'):
        return value.replace('.', '[.]')
    if kind == 'emails':
        local, _, domain = value.partition('@')
        return f"{local}[@]{domain.replace('.', '[.]')}"
    return value  # hashes, CVE ids, IPv6 - nothing a mail client would linkify


# --- Extraction -------------------------------------------------------------

# File extensions that are *also* real TLDs (or 2-letter ccTLDs), and show up
# in analyst text as file names far more often than as domains. A domain in
# one of these is skipped rather than reported as an IOC.
_FILE_LIKE_TLDS = {'js', 'py', 'sh', 'md', 'so', 'cs', 'gz', 'rs', 'ts', 'rb'}

# Generic TLDs accepted for a domain candidate, on top of every 2-letter
# alphabetic ccTLD and punycode (xn--) TLD. A candidate's TLD has to be one of
# these - otherwise dotted identifiers like System.Management.Automation in a
# pasted PowerShell script would all be reported as domains. Skewed towards
# what turns up in threat reports, including the cheap TLDs abused for phishing.
_GTLDS = set("""
com net org info biz edu gov mil int name pro mobi asia tel travel jobs museum
aero coop cat xxx app dev page cloud online site website tech store shop xyz
top club live vip work click link world today space fun life news email host
hosting network systems solutions services support security digital zone
center company group agency media studio design blog wiki art game games win
bid loan date download stream review trade webcam party science racing
accountant cricket faith men gdn kim rest cfd sbs monster buzz quest bond lol
cyou beauty makeup hair skin boats yachts autos cars homes mom ink pics photo
photos pictures gallery video tube movie best one plus pink red blue black
green gold tokyo london nyc berlin paris swiss africa amsterdam tips tools
training wtf xin
""".split())

_LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
_URL_RE = re.compile(r'\b(?:https?|ftp)://[^\s<>"\'`\\]+', re.I)
_EMAIL_RE = re.compile(
    r'(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}(?![\w-])')
_HASH_RE = re.compile(r'(?<!\w)(?:[0-9A-Fa-f]{128}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?!\w)')
_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I)
_IPV4_RE = re.compile(
    r'(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w]|\.\d)')
_IPV6_RE = re.compile(r'(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:]|\.\d)')
_DOMAIN_RE = re.compile(rf'(?<![\w@.-])(?:{_LABEL}\.)+(?:[a-z]{{2,24}}|xn--[a-z0-9-]{{2,59}})(?![\w-])', re.I)

_HASH_KINDS = {32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'}

CATEGORIES = ['urls', 'ipv4', 'ipv6', 'domains', 'emails', 'md5', 'sha1', 'sha256', 'sha512', 'cves']

# URL trailing characters that are almost always sentence punctuation
# wrapped around the link rather than part of it.
_URL_TRAILING = '.,;:!?\'">]}'


def _trim_url(url: str) -> str:
    # A closing paren is only part of the URL if it balances an opening one
    # (wikipedia-style /page_(1)); otherwise it's the sentence's own ")".
    while url and (url[-1] in _URL_TRAILING or (url[-1] == ')' and url.count(')') > url.count('('))):
        url = url[:-1]
    return url


def _domain_ok(domain: str) -> bool:
    domain = domain.lower().rstrip('.')
    if len(domain) > 253 or '.' not in domain:
        return False
    tld = domain.rsplit('.', 1)[1]
    if tld in _FILE_LIKE_TLDS:
        return False
    if tld.startswith('xn--') or len(tld) == 2:
        return True
    return tld in _GTLDS


def _find_spans(text: str) -> List[Tuple[int, int, str, str]]:
    """(start, end, kind, normalized value) for every indicator in already-
    refanged text, non-overlapping. Scanned most-specific first so a domain
    inside a URL or email, or an IP inside a URL, is never double-reported as
    a standalone match."""
    taken = bytearray(len(text))
    spans: List[Tuple[int, int, str, str]] = []

    def _claim(start: int, end: int, kind: str, value: str) -> None:
        if taken[start:end].count(1):
            return
        taken[start:end] = b'\x01' * (end - start)
        spans.append((start, end, kind, value))

    for m in _URL_RE.finditer(text):
        url = _trim_url(m.group(0))
        if len(url) > len('https://'):
            _claim(m.start(), m.start() + len(url), 'urls', url)

    for m in _EMAIL_RE.finditer(text):
        _claim(m.start(), m.end(), 'emails', m.group(0).lower())

    for m in _HASH_RE.finditer(text):
        token = m.group(0)
        if re.search(r'[A-Fa-f]', token):  # all-digit runs are numbers, not hashes
            _claim(m.start(), m.end(), _HASH_KINDS[len(token)], token.lower())

    for m in _CVE_RE.finditer(text):
        _claim(m.start(), m.end(), 'cves', m.group(0).upper())

    for m in _IPV4_RE.finditer(text):
        try:
            ip = str(ipaddress.IPv4Address(m.group(0)))
        except ValueError:  # e.g. leading-zero octets - ambiguous (octal), skip
            continue
        _claim(m.start(), m.end(), 'ipv4', ip)

    for m in _IPV6_RE.finditer(text):
        token = m.group(0)
        if token.count(':') < 2 or token.strip(':') == '':
            continue
        try:
            ip = ipaddress.IPv6Address(token)
        except ValueError:
            continue
        _claim(m.start(), m.end(), 'ipv6', ip.compressed)

    for m in _DOMAIN_RE.finditer(text):
        if _domain_ok(m.group(0)):
            _claim(m.start(), m.end(), 'domains', m.group(0).lower())

    spans.sort(key=lambda s: s[0])
    return spans


def _scope_label(ip_str: str) -> str:
    ip = ipaddress.ip_address(ip_str)
    if ip.is_loopback:
        return 'loopback'
    if ip.is_link_local:
        return 'link-local'
    if ip.is_multicast:
        return 'multicast'
    if ip.is_private:
        return 'private'
    if ip.is_global:
        return 'public'
    return 'reserved'


def extract_iocs(text: str) -> Dict[str, Any]:
    """Pull every indicator out of free text (defanged or not). Returns:
      refanged  - the input with defanging undone
      defanged  - the input with every found indicator defanged
      iocs      - {category: [{'value', 'defanged', 'scope'?}]} de-duplicated
                  in first-seen order; domains and IPs that are the host of a
                  URL, or the domain of an email, are listed too
      counts / total
    """
    refanged = refang(text)
    spans = _find_spans(refanged)

    found: Dict[str, Dict[str, None]] = {cat: {} for cat in CATEGORIES}
    for _, _, kind, value in spans:
        found[kind].setdefault(value, None)
        # Hosts hiding inside URLs / email addresses are indicators too.
        if kind == 'urls':
            host = urlsplit(value).hostname or ''
            if host:
                try:
                    ip = ipaddress.ip_address(host)
                    found['ipv4' if ip.version == 4 else 'ipv6'].setdefault(ip.compressed, None)
                except ValueError:
                    if _domain_ok(host) and _DOMAIN_RE.fullmatch(host):
                        found['domains'].setdefault(host.lower(), None)
        elif kind == 'emails':
            domain = value.partition('@')[2]
            if _domain_ok(domain):
                found['domains'].setdefault(domain, None)

    iocs: Dict[str, List[Dict[str, Any]]] = {}
    for cat in CATEGORIES:
        items = []
        for value in found[cat]:
            item: Dict[str, Any] = {'value': value, 'defanged': defang_indicator(value, cat)}
            if cat in ('ipv4', 'ipv6'):
                item['scope'] = _scope_label(value)
            items.append(item)
        iocs[cat] = items

    # Defanged copy of the whole text: swap each span in place, back to front
    # so earlier offsets stay valid.
    defanged = refanged
    for start, end, kind, value in reversed(spans):
        defanged = defanged[:start] + defang_indicator(refanged[start:end], kind) + defanged[end:]

    counts = {cat: len(items) for cat, items in iocs.items()}
    return {
        'refanged': refanged,
        'defanged': defanged,
        'iocs': iocs,
        'counts': counts,
        'total': sum(counts.values()),
    }
