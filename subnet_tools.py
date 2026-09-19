"""Offline subnet / CIDR calculator - pure stdlib `ipaddress`, no network calls.

Used by app.py's /api/subnet routes (Tools tab). Accepts the ways people
actually write a network: 10.0.0.0/24, 10.0.0.0/255.255.255.0,
"10.0.0.0 255.255.255.0", a wildcard mask, a bare IP (treated as a single
host), or IPv6 equivalents.
"""

import ipaddress
import re
from itertools import islice
from typing import Any, Dict, List, Union

from ioc_tools import refang

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

MAX_SPLIT_RESULTS = 256      # rows returned for a split - the count is always exact
MAX_HOST_LIST = 16           # only list individual hosts for tiny subnets
MAX_SUMMARIZE_ENTRIES = 5000

_RANGE_RE = re.compile(r'^\s*(\S+)\s*-\s*(\S+)\s*$')

# Explicit special-purpose ranges rather than ipaddress' is_private/is_global
# flags - those are computed differently across Python versions and are
# unreliable for wide blocks (0.0.0.0/0 reports as global on some builds).
_V4_SPECIAL = [(ipaddress.ip_network(n), label) for n, label in [
    ('0.0.0.0/8', "'This network' / unspecified (0.0.0.0/8)"),
    ('10.0.0.0/8', 'Private (RFC 1918)'),
    ('100.64.0.0/10', 'Shared address space / carrier-grade NAT (RFC 6598)'),
    ('127.0.0.0/8', 'Loopback'),
    ('169.254.0.0/16', 'Link-local (APIPA)'),
    ('172.16.0.0/12', 'Private (RFC 1918)'),
    ('192.0.0.0/24', 'IETF protocol assignments (RFC 6890)'),
    ('192.0.2.0/24', 'Documentation (TEST-NET-1)'),
    ('192.168.0.0/16', 'Private (RFC 1918)'),
    ('198.18.0.0/15', 'Benchmarking (RFC 2544)'),
    ('198.51.100.0/24', 'Documentation (TEST-NET-2)'),
    ('203.0.113.0/24', 'Documentation (TEST-NET-3)'),
    ('224.0.0.0/4', 'Multicast'),
    ('240.0.0.0/4', 'Reserved (incl. 255.255.255.255 broadcast)'),
]]
_V6_SPECIAL = [(ipaddress.ip_network(n), label) for n, label in [
    ('::/128', 'Unspecified address'),
    ('::1/128', 'Loopback'),
    ('::ffff:0:0/96', 'IPv4-mapped address'),
    ('2001:db8::/32', 'Documentation (RFC 3849)'),
    ('fc00::/7', 'Unique local address (ULA, RFC 4193)'),
    ('fe80::/10', 'Link-local'),
    ('ff00::/8', 'Multicast'),
]]
_V6_GLOBAL_UNICAST = ipaddress.ip_network('2000::/3')


class SubnetError(ValueError):
    """Bad user input - the message is safe to show as-is."""


def parse_network(text: str) -> Network:
    """Parse one network in any supported notation. Host bits are allowed
    (192.168.1.77/24 -> 192.168.1.0/24); use calculate()'s input_address to
    see that the input wasn't the network address itself."""
    text = refang((text or '').strip())
    if not text:
        raise SubnetError('Enter a CIDR block, e.g. 192.168.1.0/24')

    range_match = _RANGE_RE.match(text)
    if range_match and '/' not in text:
        blocks = _range_to_networks(range_match.group(1), range_match.group(2))
        if len(blocks) == 1:
            return blocks[0]
        raise SubnetError(
            f'{text} is not a single CIDR block - it needs {len(blocks)}: '
            + ', '.join(str(b) for b in blocks[:8]) + (' ...' if len(blocks) > 8 else '')
            + '. Use the range/summarize box below for ranges.')

    # "10.0.0.0 255.255.255.0" -> "10.0.0.0/255.255.255.0"
    parts = text.split()
    if len(parts) == 2 and '/' not in text:
        text = f'{parts[0]}/{parts[1]}'
    elif len(parts) != 1:
        raise SubnetError(f"Can't read '{text}' as a network")

    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError as e:
        raise SubnetError(f"'{text}' isn't a valid network ({e})")


def _range_to_networks(first: str, last: str) -> List[Network]:
    try:
        a, b = ipaddress.ip_address(first), ipaddress.ip_address(last)
    except ValueError as e:
        raise SubnetError(f"Invalid IP in range '{first} - {last}' ({e})")
    if a.version != b.version:
        raise SubnetError(f"Range '{first} - {last}' mixes IPv4 and IPv6")
    if int(a) > int(b):
        raise SubnetError(f"Range start {first} is after its end {last}")
    return list(ipaddress.summarize_address_range(a, b))


def _scope(net: Network) -> Dict[str, Any]:
    """Human label + whether the block is publicly routable. A block that
    only partly overlaps a special-purpose range (e.g. 8.0.0.0/5, which
    contains 10.0.0.0/8) is reported as spanning several types."""
    special = _V4_SPECIAL if net.version == 4 else _V6_SPECIAL
    for known, label in special:
        if net.subnet_of(known):
            return {'scope': label, 'is_global': False}
    if any(net.overlaps(known) for known, _ in special):
        return {'scope': 'Spans several address types (not a single scope)', 'is_global': False}
    if net.version == 6 and not net.subnet_of(_V6_GLOBAL_UNICAST):
        return {'scope': 'Reserved / not global unicast', 'is_global': False}
    return {'scope': 'Public / globally routable', 'is_global': True}


def _reverse_zone(net: Network) -> str:
    """The in-addr.arpa / ip6.arpa zone for a block - only defined when the
    prefix falls on an octet (v4) or nibble (v6) boundary."""
    if net.version == 4:
        if net.prefixlen == 0 or net.prefixlen % 8:
            return ''
        octets = str(net.network_address).split('.')[:net.prefixlen // 8]
        return '.'.join(reversed(octets)) + '.in-addr.arpa'
    if net.prefixlen == 0 or net.prefixlen % 4:
        return ''
    nibbles = net.network_address.exploded.replace(':', '')[:net.prefixlen // 4]
    return '.'.join(reversed(nibbles)) + '.ip6.arpa'


def _host_bounds(net: Network) -> Dict[str, Any]:
    total = net.num_addresses
    if net.version == 4:
        if net.prefixlen == 32:
            return {'first_host': str(net.network_address), 'last_host': str(net.network_address), 'usable': 1}
        if net.prefixlen == 31:  # RFC 3021 point-to-point: both addresses usable
            return {'first_host': str(net.network_address), 'last_host': str(net.broadcast_address), 'usable': 2}
        return {'first_host': str(net.network_address + 1), 'last_host': str(net.broadcast_address - 1),
                'usable': total - 2}
    return {'first_host': str(net.network_address), 'last_host': str(net.broadcast_address), 'usable': total}


def _fmt(n: int) -> str:
    return f'{n:,}'


def _describe(net: Network) -> Dict[str, Any]:
    bounds = _host_bounds(net)
    host_bits = net.max_prefixlen - net.prefixlen
    info: Dict[str, Any] = {
        'version': net.version,
        'cidr': str(net),
        'network_address': str(net.network_address),
        'prefix_length': net.prefixlen,
        'first_host': bounds['first_host'],
        'last_host': bounds['last_host'],
        'total_addresses': _fmt(net.num_addresses),
        'total_addresses_pow2': f'2^{host_bits}' if host_bits else '1',
        'usable_hosts': _fmt(bounds['usable']),
        'reverse_zone': _reverse_zone(net),
    }
    info.update(_scope(net))
    if net.version == 4:
        info.update({
            'netmask': str(net.netmask),
            'wildcard': str(net.hostmask),
            'broadcast': str(net.broadcast_address),
            'binary_netmask': '.'.join(f'{int(o):08b}' for o in str(net.netmask).split('.')),
        })
    else:
        info.update({
            'compressed': net.network_address.compressed,
            'exploded': net.network_address.exploded,
            'last_address': str(net.broadcast_address),
            'slash64_count': _fmt(2 ** (64 - net.prefixlen)) if net.prefixlen <= 64 else '',
        })
    # Individual hosts only for tiny blocks - lets the UI offer per-IP lookups.
    if net.num_addresses <= MAX_HOST_LIST:
        hosts = net.hosts() if net.version == 4 and net.prefixlen < 31 else iter(net)
        info['hosts'] = [str(h) for h in hosts]
    return info


def _split(net: Network, new_prefix: int) -> Dict[str, Any]:
    if new_prefix <= net.prefixlen:
        raise SubnetError(f'Split prefix /{new_prefix} must be longer than /{net.prefixlen}')
    if new_prefix > net.max_prefixlen:
        raise SubnetError(f'Split prefix /{new_prefix} is past /{net.max_prefixlen}')
    count = 2 ** (new_prefix - net.prefixlen)
    rows = []
    for sub in islice(net.subnets(new_prefix=new_prefix), MAX_SPLIT_RESULTS):
        bounds = _host_bounds(sub)
        rows.append({'cidr': str(sub), 'first_host': bounds['first_host'],
                     'last_host': bounds['last_host'], 'usable_hosts': _fmt(bounds['usable'])})
    return {'prefix': new_prefix, 'count': _fmt(count), 'shown': len(rows),
            'truncated': count > MAX_SPLIT_RESULTS, 'subnets': rows}


def _contains(net: Network, value: str) -> Dict[str, Any]:
    value = refang((value or '').strip())
    try:
        if '/' in value:
            other: Any = ipaddress.ip_network(value, strict=False)
        else:
            other = ipaddress.ip_address(value)
    except ValueError:
        raise SubnetError(f"'{value}' isn't a valid IP address or CIDR block")
    if other.version != net.version:
        return {'value': value, 'relation': 'version_mismatch',
                'text': f'{value} is IPv{other.version}, {net} is IPv{net.version}'}
    if isinstance(other, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        inside = other in net
        return {'value': value, 'relation': 'inside' if inside else 'outside',
                'text': f'{value} is {"inside" if inside else "NOT inside"} {net}'}
    if other.subnet_of(net):
        rel, text = 'inside', f'{other} is fully inside {net}'
    elif net.subnet_of(other):
        rel, text = 'contains', f'{other} fully contains {net}'
    elif other.overlaps(net):
        rel, text = 'overlaps', f'{other} overlaps {net}'
    else:
        rel, text = 'outside', f'{other} and {net} do not overlap'
    return {'value': value, 'relation': rel, 'text': text}


def calculate(text: str, split_prefix: Union[int, None] = None,
              contains: str = '') -> Dict[str, Any]:
    """Full breakdown of one network, plus an optional split into smaller
    subnets and an optional "is this IP/CIDR inside it?" check."""
    net = parse_network(text)
    result = _describe(net)

    # If the user typed a host address (192.168.1.77/24), say so - the
    # network address the calculator reports differs from what they entered.
    first_token = refang(text).strip().split('/')[0].split()[0] if text.strip() else ''
    try:
        given = str(ipaddress.ip_address(first_token))
        if given != str(net.network_address) and net.num_addresses > 1:
            result['input_address'] = given
    except ValueError:
        pass

    if split_prefix is not None:
        result['split'] = _split(net, split_prefix)
    if contains and contains.strip():
        result['contains'] = _contains(net, contains)
    return result


def summarize(text: str) -> Dict[str, Any]:
    """Merge a list of CIDRs / IPs / "start - end" ranges (one per line, or
    comma/semicolon separated) into the smallest equivalent set of CIDR
    blocks. Bad lines are reported individually rather than failing the batch."""
    entries = [e.strip() for e in re.split(r'[\n,;]+', text or '') if e.strip()]
    if not entries:
        raise SubnetError('Enter one or more CIDR blocks, IPs, or ranges (start - end), one per line')
    if len(entries) > MAX_SUMMARIZE_ENTRIES:
        raise SubnetError(f'Too many entries ({len(entries)}) - the limit is {MAX_SUMMARIZE_ENTRIES}')

    nets: Dict[int, List[Network]] = {4: [], 6: []}
    invalid: List[Dict[str, str]] = []
    for entry in entries:
        try:
            m = _RANGE_RE.match(refang(entry))
            if m and '/' not in entry:
                blocks = _range_to_networks(m.group(1), m.group(2))
            else:
                blocks = [parse_network(entry)]
        except SubnetError as e:
            invalid.append({'entry': entry, 'error': str(e)})
            continue
        for block in blocks:
            nets[block.version].append(block)

    merged: List[Network] = []
    for version in (4, 6):
        merged.extend(ipaddress.collapse_addresses(nets[version]))

    return {
        'input_count': len(entries),
        'networks': [{'cidr': str(n), 'total_addresses': _fmt(n.num_addresses)} for n in merged],
        'total_addresses': _fmt(sum(n.num_addresses for n in merged)),
        'invalid': invalid,
    }


_CIDR_LIKE_RE = re.compile(r'^\s*(?:[0-9A-Fa-f:.]+\s*/\s*\d{1,3}|[0-9.]+\s*/\s*[0-9.]+)\s*$')


def looks_like_cidr(value: str) -> bool:
    """True for input that is unmistakably a network (has a /prefix or /mask)
    - used to route the main search box to the subnet calculator."""
    text = refang((value or '').strip())
    if not _CIDR_LIKE_RE.match(text):
        return False
    try:
        ipaddress.ip_network(text.replace(' ', ''), strict=False)
        return True
    except ValueError:
        return False
