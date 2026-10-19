"""On-demand revocation check (OCSP, then CRL) for a code-signing or
timestamp-authority certificate - backs the Digital Certificate tab's
"Check revocation" button. The tab parses files entirely in the browser,
but a browser can't query a CA's OCSP responder or download its CRL
(no CORS on those endpoints), so the certificate comes here instead.

The OCSP/CRL/CA-issuer URLs are read out of the certificate, i.e. out of an
untrusted file someone uploaded, so every fetch is restricted to publicly
routable addresses (see _PublicOnlyResolver) - otherwise a crafted
certificate could make this server probe the local network.
"""

import ipaddress
import socket
from base64 import b64decode
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, ExtensionOID

import subnet_tools
from hash_lookup import _exc_text, _new_ssl_context

MAX_URLS_PER_KIND = 4
MAX_CERT_B64_CHARS = 100_000
MAX_CERT_BYTES = 256 * 1024
MAX_CRL_BYTES = 20 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 10


class RevocationInputError(ValueError):
    """Bad request payload - reported to the caller as HTTP 400."""


class _FetchError(Exception):
    pass


def _is_public_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip.split('%', 1)[0])  # drop an IPv6 zone id
    except ValueError:
        return False
    return subnet_tools._scope(ipaddress.ip_network(address))['is_global']


class _PublicOnlyResolver(aiohttp.resolver.DefaultResolver):
    """Refuses to connect anywhere that isn't publicly routable. Checking at
    resolve time (rather than once up front) also covers DNS rebinding,
    since this is the resolution the connection actually uses."""

    async def resolve(self, host, port=0, family=socket.AF_INET):
        results = await super().resolve(host, port, family)
        for result in results:
            if not _is_public_ip(result['host']):
                raise _FetchError(f'{host} resolves to a non-public address ({result["host"]}) - refused')
        return results


def _check_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise _FetchError(f'unsupported URL {url!r}')
    # aiohttp skips the resolver for an IP literal, so check that here.
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return parsed.hostname
    if not _is_public_ip(parsed.hostname):
        raise _FetchError(f'{parsed.hostname} is not a public address - refused')
    return parsed.hostname


async def _fetch(session: aiohttp.ClientSession, url: str, max_bytes: int,
                 data: Optional[bytes] = None, headers: Optional[dict] = None) -> bytes:
    host = _check_url(url)
    method = session.post if data is not None else session.get
    async with method(url, data=data, headers=headers, allow_redirects=False) as response:
        if response.status != 200:
            raise _FetchError(f'HTTP {response.status} from {host}')
        if response.content_length and response.content_length > max_bytes:
            raise _FetchError(f'response from {host} is too large')
        body = bytearray()
        async for chunk in response.content.iter_chunked(64 * 1024):
            body += chunk
            if len(body) > max_bytes:
                raise _FetchError(f'response from {host} is too large')
        return bytes(body)


def _load_cert_b64(value: str, what: str) -> x509.Certificate:
    if not isinstance(value, str) or len(value) > MAX_CERT_B64_CHARS:
        raise RevocationInputError(f'{what} certificate is missing or too large')
    try:
        return x509.load_der_x509_certificate(b64decode(value, validate=True))
    except Exception:
        raise RevocationInputError(f'{what} certificate is not valid base64 DER')


def _urls(cert: x509.Certificate) -> Dict[str, List[str]]:
    found = {'ocsp': [], 'ca_issuers': [], 'crl': []}
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        for desc in aia:
            if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                if desc.access_method == AuthorityInformationAccessOID.OCSP:
                    found['ocsp'].append(desc.access_location.value)
                elif desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    found['ca_issuers'].append(desc.access_location.value)
    except x509.ExtensionNotFound:
        pass
    try:
        for point in cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value:
            for name in point.full_name or []:
                if isinstance(name, x509.UniformResourceIdentifier):
                    found['crl'].append(name.value)
    except x509.ExtensionNotFound:
        pass
    return {kind: [u for u in urls if u.lower().startswith(('http://', 'https://'))][:MAX_URLS_PER_KIND]
            for kind, urls in found.items()}


def _parse_issuer_download(body: bytes, leaf: x509.Certificate) -> Optional[x509.Certificate]:
    """caIssuers URLs serve a DER cert, a PEM cert, or a PKCS#7 bundle (.p7c)."""
    candidates: List[x509.Certificate] = []
    for loader in (lambda b: [x509.load_der_x509_certificate(b)],
                   lambda b: [x509.load_pem_x509_certificate(b)],
                   pkcs7.load_der_pkcs7_certificates,
                   pkcs7.load_pem_pkcs7_certificates):
        try:
            candidates = loader(body)
            break
        except Exception:
            continue
    return next((c for c in candidates if c.subject == leaf.issuer), None)


def _verify_signature(public_key, signature: bytes, data: bytes, hash_algorithm) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
    else:
        raise InvalidSignature('unsupported responder key type')


def _ocsp_responder_key(response: ocsp.OCSPResponse, issuer: x509.Certificate):
    """The CA itself, or a delegated responder cert the CA issued with the
    OCSP-signing EKU (RFC 6960 4.2.2.2) - anything else isn't trusted."""
    issuer_key_hash = x509.SubjectKeyIdentifier.from_public_key(issuer.public_key()).digest
    if response.responder_name == issuer.subject or response.responder_key_hash == issuer_key_hash:
        return issuer.public_key()
    for cert in response.certificates:
        try:
            cert.verify_directly_issued_by(issuer)
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except Exception:
            continue
        if ExtendedKeyUsageOID.OCSP_SIGNING in eku:
            return cert.public_key()
    return None


async def _check_ocsp(session, leaf, issuer, url) -> Dict[str, Any]:
    request = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1()).build()
    body = await _fetch(session, url, MAX_CERT_BYTES, data=request.public_bytes(serialization.Encoding.DER),
                        headers={'Content-Type': 'application/ocsp-request'})
    response = ocsp.load_der_ocsp_response(body)
    host = urlparse(url).hostname
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise _FetchError(f'OCSP responder {host} answered {response.response_status.name.lower()}')
    if response.serial_number != leaf.serial_number:
        raise _FetchError(f'OCSP responder {host} answered for a different certificate')
    responder_key = _ocsp_responder_key(response, issuer)
    if responder_key is None:
        raise _FetchError(f'OCSP response from {host} is not signed by the issuing CA')
    try:
        _verify_signature(responder_key, response.signature, response.tbs_response_bytes,
                          response.signature_hash_algorithm)
    except InvalidSignature:
        raise _FetchError(f'OCSP response from {host} has an invalid signature')

    status = response.certificate_status
    if status == ocsp.OCSPCertStatus.GOOD:
        return {'status': 'good', 'method': 'OCSP', 'responder': host}
    if status == ocsp.OCSPCertStatus.REVOKED:
        return {'status': 'revoked', 'method': 'OCSP', 'responder': host,
                'revoked_at': response.revocation_time_utc.isoformat(),
                'reason': response.revocation_reason.value if response.revocation_reason else None}
    return {'status': 'unknown', 'method': 'OCSP', 'responder': host,
            'note': f'OCSP responder {host} does not know this certificate'}


async def _check_crl(session, leaf, issuer, url) -> Dict[str, Any]:
    body = await _fetch(session, url, MAX_CRL_BYTES)
    try:
        crl = x509.load_der_x509_crl(body)
    except ValueError:
        crl = x509.load_pem_x509_crl(body)
    host = urlparse(url).hostname
    if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
        raise _FetchError(f'CRL from {host} is not signed by the issuing CA')

    revoked = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    if revoked is None:
        return {'status': 'good', 'method': 'CRL', 'responder': host}
    try:
        reason = revoked.extensions.get_extension_for_class(x509.CRLReason).value.reason.value
    except x509.ExtensionNotFound:
        reason = None
    return {'status': 'revoked', 'method': 'CRL', 'responder': host,
            'revoked_at': revoked.revocation_date_utc.isoformat(), 'reason': reason}


async def check_revocation(leaf_der_b64: str, issuer_der_b64: Optional[str] = None) -> Dict[str, Any]:
    """{'status': 'good'|'revoked'|'unknown', 'method', 'responder',
    'revoked_at', 'reason', 'note'}. Network problems never raise - they end
    up in 'note' with status 'unknown'. Bad input raises RevocationInputError."""
    leaf = _load_cert_b64(leaf_der_b64, 'Leaf')
    issuer = _load_cert_b64(issuer_der_b64, 'Issuer') if issuer_der_b64 else None
    if issuer is not None and issuer.subject != leaf.issuer:
        issuer = None  # not actually this cert's issuer - fetch the right one

    urls = _urls(leaf)
    if not urls['ocsp'] and not urls['crl']:
        return {'status': 'unknown', 'note': 'The certificate lists no OCSP responder or CRL to check against'}

    notes: List[str] = []
    connector = aiohttp.TCPConnector(resolver=_PublicOnlyResolver(), ssl=_new_ssl_context())
    async with aiohttp.ClientSession(connector=connector,
                                     timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)) as session:
        for url in urls['ca_issuers'] if issuer is None else []:
            try:
                issuer = _parse_issuer_download(await _fetch(session, url, MAX_CERT_BYTES), leaf)
            except Exception as e:
                notes.append(f'issuer download failed: {_exc_text(e)}')
            if issuer is not None:
                break
        if issuer is None:
            notes.append("couldn't obtain the issuing CA certificate needed to verify the answer")
            return {'status': 'unknown', 'note': '; '.join(notes)}

        # OCSP first (small, current); the CRL only if OCSP gives no answer.
        for check, kind in ((_check_ocsp, 'ocsp'), (_check_crl, 'crl')):
            for url in urls[kind]:
                try:
                    result = await check(session, leaf, issuer, url)
                except Exception as e:
                    notes.append(f'{kind.upper()} check failed: {_exc_text(e)}')
                    continue
                if result['status'] != 'unknown':
                    return result
                notes.append(result['note'])

    return {'status': 'unknown', 'note': '; '.join(notes) or 'No revocation source answered'}
