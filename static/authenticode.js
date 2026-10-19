/*
 * Client-side Authenticode digital-signature parser + renderer for Windows
 * PE files (.exe/.dll/.sys/...) and Windows Installer packages (.msi).
 *
 * Covers:
 *   - Locating the WIN_CERTIFICATE table in the PE (supports dual SHA-1 +
 *     SHA-256 signing, i.e. multiple embedded signature blobs)
 *   - For an MSI (an OLE compound file, not a PE): reading the hidden
 *     "DigitalSignature" stream, which holds the same PKCS#7 blob
 *   - Parsing the embedded PKCS#7/Authenticode SignedData structure with a
 *     minimal hand-rolled DER reader (no external dependencies)
 *   - Walking the certificate chain (signer -> intermediates -> root)
 *   - Extracting the RFC3161 (or legacy) counter-signature timestamp
 *   - Recomputing the file digest (Authenticode page-hash for a PE, the MSI
 *     stream-walk digest for an MSI) and comparing it to the digest embedded
 *     in the signature, to flag tampering after signing
 */
(function (global) {
  'use strict';

  // ===================== Minimal DER/BER reader =====================

  const CLASS_UNIVERSAL = 0x00;
  const CLASS_CONTEXT = 0x80;

  // Every node's `value` (content bytes) and `raw` (full TLV bytes) are
  // plain Uint8Array *views* into the original buffer - parsing never
  // copies, so a single WIN_CERTIFICATE blob can be walked recursively
  // just by re-slicing.
  function parseTLV(view) {
    let pos = 0;
    const first = view[pos++];
    const tagClass = first & 0xc0;
    const constructed = !!(first & 0x20);
    let tagNum = first & 0x1f;
    if (tagNum === 0x1f) {
      tagNum = 0;
      let b;
      do {
        b = view[pos++];
        tagNum = (tagNum << 7) | (b & 0x7f);
      } while (b & 0x80);
    }
    const lenByte = view[pos++];
    let length;
    if (lenByte & 0x80) {
      const n = lenByte & 0x7f;
      if (n === 0) throw new Error('Indefinite-length DER is not supported');
      length = 0;
      for (let i = 0; i < n; i++) length = length * 256 + view[pos++];
    } else {
      length = lenByte;
    }
    const valueStart = pos;
    const valueEnd = valueStart + length;
    if (valueEnd > view.length) throw new Error('ASN.1 length exceeds buffer');
    return {
      tagClass,
      tagNum,
      constructed,
      totalLen: valueEnd,
      value: view.subarray(valueStart, valueEnd),
      raw: view.subarray(0, valueEnd),
    };
  }

  function readChildren(view) {
    const out = [];
    let pos = 0;
    while (pos < view.length) {
      const node = parseTLV(view.subarray(pos));
      out.push(node);
      pos += node.totalLen;
    }
    return out;
  }

  function decodeOid(bytes) {
    if (!bytes.length) return '';
    let s = Math.floor(bytes[0] / 40) + '.' + (bytes[0] % 40);
    let val = 0;
    for (let i = 1; i < bytes.length; i++) {
      val = val * 128 + (bytes[i] & 0x7f);
      if (!(bytes[i] & 0x80)) {
        s += '.' + val;
        val = 0;
      }
    }
    return s;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  function bytesToInt(bytes) {
    let v = 0;
    for (const b of bytes) v = v * 256 + b;
    return v;
  }

  function parseUTCTime(s) {
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) return null;
    const yy = +m[1];
    const year = yy < 50 ? 2000 + yy : 1900 + yy;
    return new Date(Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  }

  function parseGeneralizedTime(s) {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(s);
    if (!m) return null;
    return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  }

  function nodeToDate(node) {
    if (!node) return null;
    const s = new TextDecoder('ascii').decode(node.value);
    if (node.tagNum === 23) return parseUTCTime(s); // UTCTime
    if (node.tagNum === 24) return parseGeneralizedTime(s); // GeneralizedTime
    return null;
  }

  function nodeToString(node) {
    try {
      if (node.tagNum === 30) {
        // BMPString - UTF-16BE
        let s = '';
        for (let i = 0; i + 1 < node.value.length; i += 2) {
          s += String.fromCharCode((node.value[i] << 8) | node.value[i + 1]);
        }
        return s;
      }
      return new TextDecoder('utf-8').decode(node.value);
    } catch (e) {
      return bytesToHex(node.value);
    }
  }

  // ===================== OID name tables =====================

  const OID_NAMES = {
    '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C',
    '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.5': 'serialNumber',
    '2.5.4.9': 'STREET', '1.2.840.113549.1.9.1': 'E',
  };
  const HASH_ALG_NAMES = {
    '1.2.840.113549.2.5': 'MD5',
    '1.3.14.3.2.26': 'SHA-1',
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
    '2.16.840.1.101.3.4.2.2': 'SHA-384',
    '2.16.840.1.101.3.4.2.3': 'SHA-512',
  };
  const SIG_ALG_NAMES = {
    '1.2.840.113549.1.1.4': 'MD5 with RSA',
    '1.2.840.113549.1.1.5': 'SHA-1 with RSA',
    '1.2.840.113549.1.1.11': 'SHA-256 with RSA',
    '1.2.840.113549.1.1.12': 'SHA-384 with RSA',
    '1.2.840.113549.1.1.13': 'SHA-512 with RSA',
    '1.2.840.10045.4.1': 'SHA-1 with ECDSA',
    '1.2.840.10045.4.3.2': 'SHA-256 with ECDSA',
    '1.2.840.10045.4.3.3': 'SHA-384 with ECDSA',
    '1.2.840.10045.4.3.4': 'SHA-512 with ECDSA',
  };
  const EKU_NAMES = {
    '1.3.6.1.5.5.7.3.3': 'Code Signing',
    '1.3.6.1.5.5.7.3.8': 'Time Stamping',
    '1.3.6.1.5.5.7.3.1': 'Server Authentication',
    '1.3.6.1.5.5.7.3.2': 'Client Authentication',
  };

  const WEBCRYPTO_HASH_NAMES = new Set(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']);

  // ===================== Known leaked / abused code-signing certificates =====================
  // A small, sourced sample - matched by certificate serial number (unique
  // per issuing CA) - NOT a comprehensive feed. Pulled from the
  // community-maintained ReversecLabs/lolcerts project (github.com/ReversecLabs/lolcerts,
  // csv/leaked.csv + csv/malicious.csv, fetched 2026-08-06). Extend this list
  // as new incidents are documented; each entry cites its source.
  const KNOWN_ABUSED_CERTS = [
    { serial: '0b886032861d9553c68f803313a98975', issuer: 'DigiCert SHA2 Assured ID Code Signing CA', note: 'MicroStar International (MSI) - private code-signing key leaked in a 2023 ransomware breach', ref: 'https://thehackernews.com/2023/05/msi-data-breach-private-code-signing.html' },
    { serial: '43bb437d609866286dd839e1d00309f5', issuer: 'VeriSign Class 3 Code Signing 2010 CA', note: 'NVIDIA - certificate leaked in the March 2022 LAPSUS$ breach, later used to sign malware', ref: 'https://www.malwarebytes.com/blog/news/2022/03/stolen-nvidia-certificates-used-to-sign-malware-heres-what-to-do' },
    { serial: '14781bc862e8dc503a559346f5dcc518', issuer: 'VeriSign Class 3 Code Signing 2010 CA', note: 'NVIDIA - certificate leaked in the March 2022 LAPSUS$ breach, later used to sign malware', ref: 'https://www.malwarebytes.com/blog/news/2022/03/stolen-nvidia-certificates-used-to-sign-malware-heres-what-to-do' },
    { serial: '0139dde119bb320dfb9f5defe3f71245', issuer: 'Sectigo Public Code Signing CA R36', note: 'Hangil IT Co., Ltd - leaked certificate used by various malware', ref: '' },
    { serial: '0dbf152deaf0b981a8a938d53f769db8', issuer: 'DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1', note: "AnyDesk - revoked after the company's Feb 2024 public breach statement", ref: 'https://anydesk.com/en/public-statement' },
    { serial: '879fa942f9f097b74fd6f7dabcf1745a', issuer: 'LAMERA CORPORATION LIMITED', note: 'Used to sign malware attributed to North Korean state actors', ref: 'https://labs.withsecure.com/publications/no-pineapple-dprk-targeting-of-medical-research-and-technology-sector' },
    { serial: '0f1b43484a1369c83038dc24e7778b7d', issuer: 'VeriSign Class 3 Code Signing 2010 CA', note: 'Used by Hacking Team (offensive-security vendor) to sign surveillance tools', ref: 'https://www.trendmicro.com/vinfo/fr/security/news/vulnerabilities-and-exploits/the-hacking-team-leak-zero-days-patches-and-more-zero-days' },
  ];

  function normalizeSerial(hex) {
    let h = String(hex || '').toLowerCase().replace(/[^0-9a-f]/g, '');
    while (h.length > 2 && h.startsWith('00')) h = h.slice(2);
    return h;
  }

  function findKnownBadCert(cert) {
    if (!cert) return null;
    const serial = normalizeSerial(cert.serialHex);
    return KNOWN_ABUSED_CERTS.find((e) => e.serial === serial) || null;
  }

  // ===================== X.501 Name / X.509 certificate =====================

  function parseName(nameNode) {
    const rdns = readChildren(nameNode.value); // SEQUENCE OF RDN (each a SET)
    const attrs = {};
    const parts = [];
    for (const rdn of rdns) {
      for (const ava of readChildren(rdn.value)) {
        const [oidNode, valNode] = readChildren(ava.value);
        const oid = decodeOid(oidNode.value);
        const label = OID_NAMES[oid] || oid;
        const val = nodeToString(valNode);
        if (!(label in attrs)) attrs[label] = val;
        parts.push(`${label}=${val}`);
      }
    }
    return {
      attrs,
      string: parts.join(', '),
      cn: attrs.CN || attrs.O || parts[0] || '(unknown)',
    };
  }

  // GeneralName uniformResourceIdentifier is [6] IA5String - collect every
  // one under `node` (CRL distribution points nest them a few levels deep).
  function collectUris(node, out) {
    if (node.tagClass === CLASS_CONTEXT && node.tagNum === 6 && !node.constructed) {
      out.push(String.fromCharCode(...node.value));
    } else if (node.constructed) {
      for (const child of readChildren(node.value)) collectUris(child, out);
    }
    return out;
  }

  function decodeExtensions(extensionsNode) {
    const ekus = [];
    let isCA = null;
    const crlUrls = [];
    const ocspUrls = [];
    const caIssuerUrls = [];
    try {
      const extSeq = readChildren(extensionsNode.value)[0]; // SEQUENCE OF Extension
      for (const ext of readChildren(extSeq.value)) {
        const extChildren = readChildren(ext.value);
        const extOid = decodeOid(extChildren[0].value);
        const octet = extChildren[extChildren.length - 1]; // extnValue OCTET STRING (skips optional critical BOOLEAN)
        if (extOid === '2.5.29.37') {
          // extKeyUsage: OCTET STRING wraps SEQUENCE OF OID
          const seq = parseTLV(octet.value);
          for (const o of readChildren(seq.value)) {
            const oid = decodeOid(o.value);
            ekus.push(EKU_NAMES[oid] || oid);
          }
        } else if (extOid === '2.5.29.19') {
          // basicConstraints: SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
          const seq = parseTLV(octet.value);
          const kids = readChildren(seq.value);
          isCA = kids.length > 0 && kids[0].value.length > 0 && kids[0].value[0] !== 0;
        } else if (extOid === '2.5.29.31') {
          // cRLDistributionPoints
          collectUris(parseTLV(octet.value), crlUrls);
        } else if (extOid === '1.3.6.1.5.5.7.1.1') {
          // authorityInfoAccess: SEQUENCE OF { accessMethod OID, accessLocation GeneralName }
          for (const ad of readChildren(parseTLV(octet.value).value)) {
            const [method, location] = readChildren(ad.value);
            const target = { '1.3.6.1.5.5.7.48.1': ocspUrls, '1.3.6.1.5.5.7.48.2': caIssuerUrls }[decodeOid(method.value)];
            if (target) collectUris(location, target);
          }
        }
      }
    } catch (e) {
      /* best-effort */
    }
    return { ekus, isCA, crlUrls, ocspUrls, caIssuerUrls };
  }

  function bytesToBase64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  async function parseCertificate(certNode) {
    const [tbs, sigAlgNode] = readChildren(certNode.value);
    const tbsChildren = readChildren(tbs.value);
    let idx = 0;
    let version = 1;
    if (tbsChildren[idx].tagClass === CLASS_CONTEXT && tbsChildren[idx].tagNum === 0) {
      const verInt = readChildren(tbsChildren[idx].value)[0];
      version = bytesToInt(verInt.value) + 1;
      idx++;
    }
    const serialNode = tbsChildren[idx++];
    const serialHex = bytesToHex(serialNode.value);
    idx++; // signature AlgorithmIdentifier (inside TBS) - ignored, we use the outer one
    const issuerNode = tbsChildren[idx++];
    const validityNode = tbsChildren[idx++];
    const [notBeforeNode, notAfterNode] = readChildren(validityNode.value);
    const subjectNode = tbsChildren[idx++];
    const spkiNode = tbsChildren[idx++];

    let extensionsNode = null;
    for (let i = idx; i < tbsChildren.length; i++) {
      const c = tbsChildren[i];
      if (c.tagClass === CLASS_CONTEXT && c.tagNum === 3) extensionsNode = c;
    }

    const issuer = parseName(issuerNode);
    const subject = parseName(subjectNode);
    const notBefore = nodeToDate(notBeforeNode);
    const notAfter = nodeToDate(notAfterNode);
    const sigAlgOid = decodeOid(readChildren(sigAlgNode.value)[0].value);

    const spkiChildren = readChildren(spkiNode.value);
    const spkiAlgOid = decodeOid(readChildren(spkiChildren[0].value)[0].value);
    let keyBits = null;
    try {
      if (spkiAlgOid === '1.2.840.113549.1.1.1') {
        // RSA: BIT STRING wraps SEQUENCE { modulus INTEGER, exponent INTEGER }
        const bitstr = spkiChildren[1];
        const rsaSeq = parseTLV(bitstr.value.subarray(1)); // skip "unused bits" byte
        const [modulus] = readChildren(rsaSeq.value);
        let i = 0;
        while (i < modulus.value.length - 1 && modulus.value[i] === 0) i++;
        keyBits = (modulus.value.length - i) * 8;
      }
    } catch (e) {
      /* best-effort */
    }

    const { ekus, isCA, crlUrls, ocspUrls, caIssuerUrls } = extensionsNode
      ? decodeExtensions(extensionsNode)
      : { ekus: [], isCA: null, crlUrls: [], ocspUrls: [], caIssuerUrls: [] };

    const der = certNode.raw;
    const [thumbSha1, thumbSha256] = await Promise.all([
      crypto.subtle.digest('SHA-1', der).then((d) => bytesToHex(new Uint8Array(d))),
      crypto.subtle.digest('SHA-256', der).then((d) => bytesToHex(new Uint8Array(d))),
    ]);

    return {
      version, serialHex, issuer, subject, notBefore, notAfter,
      sigAlgorithm: SIG_ALG_NAMES[sigAlgOid] || sigAlgOid,
      publicKeyAlgorithm: spkiAlgOid === '1.2.840.113549.1.1.1' ? 'RSA'
        : spkiAlgOid === '1.2.840.10045.2.1' ? 'ECDSA' : spkiAlgOid,
      publicKeyBits: keyBits,
      ekus, isCA, crlUrls, ocspUrls, caIssuerUrls,
      thumbprintSha1: thumbSha1,
      thumbprintSha256: thumbSha256,
      issuerAndSerialKey: issuer.string + '|' + serialHex,
      derB64: bytesToBase64(der), // for the backend revocation check
    };
  }

  // ===================== PKCS#7 SignerInfo =====================

  function readAttributes(attrSetNode) {
    // attrSetNode: [0]/[1] IMPLICIT SET OF Attribute { type OID, values SET OF ANY }
    const attrs = {};
    for (const a of readChildren(attrSetNode.value)) {
      const [oidNode, valuesSetNode] = readChildren(a.value);
      attrs[decodeOid(oidNode.value)] = readChildren(valuesSetNode.value);
    }
    return attrs;
  }

  function decodeSpcString(node) {
    // SpcString ::= CHOICE { unicode [0] IMPLICIT BMPString, ascii [1] IMPLICIT IA5String }
    if (node.tagNum === 0) {
      let s = '';
      for (let i = 0; i + 1 < node.value.length; i += 2) {
        s += String.fromCharCode((node.value[i] << 8) | node.value[i + 1]);
      }
      return s;
    }
    return new TextDecoder('ascii').decode(node.value);
  }

  function parseSpcOpusInfo(opusSeqNode) {
    // SpcSpOpusInfo ::= SEQUENCE { programName [0] EXPLICIT SpcString OPTIONAL,
    //                              moreInfo    [1] EXPLICIT SpcLink OPTIONAL }
    let programName = null;
    let moreInfoUrl = null;
    for (const c of readChildren(opusSeqNode.value)) {
      if (c.tagClass === CLASS_CONTEXT && c.tagNum === 0) {
        const inner = readChildren(c.value)[0];
        if (inner) programName = decodeSpcString(inner);
      } else if (c.tagClass === CLASS_CONTEXT && c.tagNum === 1) {
        const linkInner = readChildren(c.value)[0];
        if (linkInner && linkInner.tagNum === 0) {
          moreInfoUrl = new TextDecoder('ascii').decode(linkInner.value);
        }
      }
    }
    return { programName, moreInfoUrl };
  }

  function parseSignerInfo(siNode, certsByKey) {
    const children = readChildren(siNode.value);
    let idx = 0;
    idx++; // version
    const iasNode = children[idx++]; // issuerAndSerialNumber
    const [issuerNode, serialNode] = readChildren(iasNode.value);
    const key = parseName(issuerNode).string + '|' + bytesToHex(serialNode.value);
    const cert = certsByKey[key] || null;

    const digestAlgOid = decodeOid(readChildren(children[idx++].value)[0].value);

    let authAttrs = null;
    if (children[idx] && children[idx].tagClass === CLASS_CONTEXT && children[idx].tagNum === 0) {
      authAttrs = readAttributes(children[idx]);
      idx++;
    }

    idx++; // digestEncryptionAlgorithm
    idx++; // encryptedDigest

    let unauthAttrs = null;
    if (children[idx] && children[idx].tagClass === CLASS_CONTEXT && children[idx].tagNum === 1) {
      unauthAttrs = readAttributes(children[idx]);
      idx++;
    }

    let signingTime = null;
    if (authAttrs && authAttrs['1.2.840.113549.1.9.5']) {
      signingTime = nodeToDate(authAttrs['1.2.840.113549.1.9.5'][0]);
    }

    let programName = null;
    let moreInfoUrl = null;
    if (authAttrs && authAttrs['1.3.6.1.4.1.311.2.1.12']) {
      try {
        ({ programName, moreInfoUrl } = parseSpcOpusInfo(authAttrs['1.3.6.1.4.1.311.2.1.12'][0]));
      } catch (e) {
        /* best-effort */
      }
    }

    return {
      cert,
      digestAlgorithm: HASH_ALG_NAMES[digestAlgOid] || digestAlgOid,
      signingTime, programName, moreInfoUrl, unauthAttrs,
    };
  }

  // A CertificateSet (RFC 5652 CertificateChoices) can legally contain
  // non-Certificate alternatives (attribute certs, "other" formats) tagged
  // with a context-specific class. Only [UNIVERSAL, SEQUENCE] entries are
  // plain X.509 certificates - skip anything else rather than misparse it.
  function isPlainCertificateNode(node) {
    return node.tagClass === CLASS_UNIVERSAL && node.tagNum === 16;
  }

  async function parseCertificateSet(setNode) {
    const certs = [];
    for (const cn of readChildren(setNode.value)) {
      if (isPlainCertificateNode(cn)) certs.push(await parseCertificate(cn));
    }
    return certs;
  }

  // ===================== PKCS#7 SignedData (Authenticode) =====================

  async function parsePkcs7(derBytes) {
    const contentInfo = parseTLV(derBytes);
    const [contentTypeNode, wrapperNode] = readChildren(contentInfo.value);
    if (decodeOid(contentTypeNode.value) !== '1.2.840.113549.1.7.2') {
      throw new Error('Not a PKCS#7 SignedData structure');
    }
    const signedDataNode = readChildren(wrapperNode.value)[0]; // [0] EXPLICIT SignedData
    const sdChildren = readChildren(signedDataNode.value);
    let idx = 0;
    idx++; // version
    idx++; // digestAlgorithms
    const contentInfoInner = sdChildren[idx++]; // SEQUENCE { contentType, [0] EXPLICIT content }
    const [, innerContentWrapper] = readChildren(contentInfoInner.value);

    let fileDigestHex = null;
    let fileDigestAlgOid = null;
    if (innerContentWrapper) {
      // SpcIndirectDataContent ::= SEQUENCE { data SpcAttributeTypeAndOptionalValue, messageDigest DigestInfo }
      const spcSeq = readChildren(innerContentWrapper.value)[0];
      const spcChildren = readChildren(spcSeq.value);
      const digestInfoChildren = readChildren(spcChildren[1].value);
      fileDigestAlgOid = decodeOid(readChildren(digestInfoChildren[0].value)[0].value);
      fileDigestHex = bytesToHex(digestInfoChildren[1].value);
    }

    let certs = [];
    let next = sdChildren[idx];
    if (next && next.tagClass === CLASS_CONTEXT && next.tagNum === 0) {
      certs = await parseCertificateSet(next);
      idx++;
      next = sdChildren[idx];
    }
    if (next && next.tagClass === CLASS_CONTEXT && next.tagNum === 1) {
      idx++; // crls - not used
      next = sdChildren[idx];
    }

    const certsByKey = {};
    for (const c of certs) certsByKey[c.issuerAndSerialKey] = c;

    const signerInfos = readChildren(next.value).map((n) => parseSignerInfo(n, certsByKey));

    return {
      fileDigestHex,
      fileDigestAlgorithm: HASH_ALG_NAMES[fileDigestAlgOid] || fileDigestAlgOid,
      certs, signerInfos, certsByKey,
    };
  }

  // Extracts the counter-signature timestamp attached to the *first*
  // SignerInfo's unauthenticated attributes, if present. Supports both the
  // legacy PKCS#9 countersignature attribute and the modern RFC3161
  // szOID_RFC3161_counterSign attribute used by current signing tools.
  async function extractTimestamp(signerInfo, outerCertsByKey) {
    if (!signerInfo.unauthAttrs) return null;
    const ua = signerInfo.unauthAttrs;

    if (ua['1.2.840.113549.1.9.6']) {
      // Legacy: value IS a SignerInfo directly.
      const cs = parseSignerInfo(ua['1.2.840.113549.1.9.6'][0], outerCertsByKey);
      return { type: 'legacy', time: cs.signingTime, signerCert: cs.cert, digestAlgorithm: cs.digestAlgorithm };
    }

    if (ua['1.3.6.1.4.1.311.3.3.1']) {
      // RFC3161: value is a full ContentInfo wrapping a nested SignedData
      // whose content is a TSTInfo (which carries the trusted genTime).
      const [ctOid, ctWrap] = readChildren(ua['1.3.6.1.4.1.311.3.3.1'][0].value);
      if (decodeOid(ctOid.value) !== '1.2.840.113549.1.7.2') {
        return { type: 'rfc3161', time: null, signerCert: null, error: 'Unrecognized timestamp content type' };
      }
      const tsSignedDataNode = readChildren(ctWrap.value)[0];
      const tsChildren = readChildren(tsSignedDataNode.value);
      let idx = 0;
      idx++; // version
      idx++; // digestAlgorithms
      const tsContentInfo = tsChildren[idx++];
      const [, tstWrap] = readChildren(tsContentInfo.value);

      let genTime = null;
      if (tstWrap) {
        const tstOctet = readChildren(tstWrap.value)[0]; // OCTET STRING containing DER-encoded TSTInfo
        const tstInfoSeq = parseTLV(tstOctet.value);
        // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }
        // The first 5 fields are always present in this fixed order.
        const tstFields = readChildren(tstInfoSeq.value);
        genTime = nodeToDate(tstFields[4]);
      }

      let tsCerts = [];
      let n2 = tsChildren[idx];
      if (n2 && n2.tagClass === CLASS_CONTEXT && n2.tagNum === 0) {
        tsCerts = await parseCertificateSet(n2);
        idx++;
        n2 = tsChildren[idx];
      }
      if (n2 && n2.tagClass === CLASS_CONTEXT && n2.tagNum === 1) {
        idx++;
        n2 = tsChildren[idx];
      }

      const tsCertsByKey = {};
      for (const c of tsCerts) tsCertsByKey[c.issuerAndSerialKey] = c;
      const tsSignerInfos = readChildren(n2.value).map((n) => parseSignerInfo(n, tsCertsByKey));
      const tsSigner = tsSignerInfos[0];

      return {
        type: 'rfc3161',
        time: genTime || (tsSigner && tsSigner.signingTime) || null,
        signerCert: tsSigner ? tsSigner.cert : null,
        digestAlgorithm: tsSigner ? tsSigner.digestAlgorithm : null,
        certs: tsCerts, // the TSA's own chain - lives in the token, not the outer SignedData
      };
    }

    return null;
  }

  // ===================== PE / WIN_CERTIFICATE extraction =====================

  function findPeCertBlobs(bytes) {
    if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) {
      throw new Error('Unsupported file - select a Windows executable (.exe, .dll, .sys, ...) or an installer (.msi)');
    }
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const eLfanew = dv.getUint32(0x3c, true);
    if (eLfanew + 24 > bytes.length || dv.getUint32(eLfanew, true) !== 0x00004550) {
      throw new Error('Not a valid PE file (missing "PE\\0\\0" header)');
    }
    const coffOff = eLfanew + 4;
    const sizeOfOptionalHeader = dv.getUint16(coffOff + 16, true);
    const optOff = coffOff + 20;
    if (sizeOfOptionalHeader === 0 || optOff + 2 > bytes.length) {
      throw new Error('File has no optional header - it cannot carry an Authenticode signature');
    }
    const magic = dv.getUint16(optOff, true);
    let pe32;
    if (magic === 0x10b) pe32 = true;
    else if (magic === 0x20b) pe32 = false;
    else throw new Error('Unrecognized PE optional-header magic');

    const stdSize = pe32 ? 28 : 24;
    const wsOff = optOff + stdSize;
    const imageBaseSize = pe32 ? 4 : 8;
    // ImageBase, SectionAlignment, FileAlignment, 6x version WORDs, Win32VersionValue,
    // SizeOfImage, SizeOfHeaders, then CheckSum.
    const checksumOff = wsOff + imageBaseSize + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 4 + 4 + 4;
    const dataDirOff = optOff + (pe32 ? 96 : 112);
    const secDirEntryOff = dataDirOff + 4 * 8; // IMAGE_DIRECTORY_ENTRY_SECURITY = index 4
    const secVA = dv.getUint32(secDirEntryOff, true); // file offset (not RVA) for this one directory entry
    const secSize = dv.getUint32(secDirEntryOff + 4, true);

    const blobs = [];
    if (secSize > 0) {
      let pos = secVA;
      const end = secVA + secSize;
      while (pos + 8 <= end && pos + 8 <= bytes.length) {
        const length = dv.getUint32(pos, true);
        const revision = dv.getUint16(pos + 4, true);
        const certType = dv.getUint16(pos + 6, true);
        if (length < 8 || pos + length > bytes.length) break;
        blobs.push({ offset: pos, length, revision, certType, der: bytes.subarray(pos + 8, pos + length) });
        pos += (length + 7) & ~7; // each entry is 8-byte aligned
      }
    }

    // Section table + resource directory (index 2) - only needed for the
    // version-info read below, so a malformed table just yields no sections.
    const sections = [];
    try {
      const numberOfSections = dv.getUint16(coffOff + 2, true);
      const sectionTableOff = optOff + sizeOfOptionalHeader;
      for (let i = 0; i < numberOfSections && i < 96; i++) {
        const s = sectionTableOff + i * 40;
        sections.push({
          virtualSize: dv.getUint32(s + 8, true),
          va: dv.getUint32(s + 12, true),
          rawSize: dv.getUint32(s + 16, true),
          rawPtr: dv.getUint32(s + 20, true),
        });
      }
    } catch (e) {
      /* best-effort */
    }
    const numberOfRvaAndSizes = dv.getUint32(dataDirOff - 4, true);
    const rsrcRva = numberOfRvaAndSizes > 2 ? dv.getUint32(dataDirOff + 2 * 8, true) : 0;

    return { pe32, checksumOff, secDirEntryOff, secVA, secSize, blobs, sections, rsrcRva };
  }

  // ===================== PE version info (VS_VERSIONINFO) =====================

  function rvaToOffset(peMeta, rva) {
    for (const s of peMeta.sections) {
      if (rva >= s.va && rva < s.va + Math.max(s.virtualSize, s.rawSize)) {
        const off = s.rawPtr + (rva - s.va);
        return off < s.rawPtr + s.rawSize ? off : -1;
      }
    }
    return -1;
  }

  function readUtf16z(bytes, off, end) {
    let s = '';
    while (off + 1 < end) {
      const c = bytes[off] | (bytes[off + 1] << 8);
      off += 2;
      if (!c) break;
      s += String.fromCharCode(c);
    }
    return [s, off];
  }

  const align4 = (off) => (off + 3) & ~3;

  // One node of the VS_VERSIONINFO tree: wLength, wValueLength, wType,
  // szKey (UTF-16, NUL-terminated), padding, Value, padding, Children.
  function readVersionBlock(bytes, dv, off, limit) {
    const length = dv.getUint16(off, true);
    const valueLength = dv.getUint16(off + 2, true);
    const type = dv.getUint16(off + 4, true);
    const end = Math.min(off + length, limit);
    if (length < 6 || end <= off) return null;
    const [key, afterKey] = readUtf16z(bytes, off + 6, end);
    const valueOff = align4(afterKey);
    const childOff = align4(valueOff + (type === 1 ? valueLength * 2 : valueLength));
    return { key, valueOff, childOff, end };
  }

  function versionChildren(bytes, dv, block) {
    const out = [];
    let pos = block.childOff;
    while (pos + 6 <= block.end) {
      const child = readVersionBlock(bytes, dv, pos, block.end);
      if (!child) break;
      out.push(child);
      pos = align4(child.end);
    }
    return out;
  }

  const VERSION_FIELDS = ['CompanyName', 'ProductName', 'FileDescription', 'OriginalFilename',
    'InternalName', 'FileVersion', 'LegalCopyright'];

  // The publisher/product strings a PE declares about itself (what Explorer
  // shows under Properties > Details). Returns null when there are none;
  // never throws - a malformed resource must not break signature analysis.
  function parseVersionInfo(bytes, peMeta) {
    try {
      if (!peMeta.rsrcRva) return null;
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const rsrcOff = rvaToOffset(peMeta, peMeta.rsrcRva);
      if (rsrcOff < 0) return null;

      // IMAGE_RESOURCE_DIRECTORY: named + ID entry counts at +12/+14, then
      // 8-byte entries {Name/Id, OffsetToData}; high bit = subdirectory.
      const entries = (dirOff) => {
        const count = dv.getUint16(dirOff + 12, true) + dv.getUint16(dirOff + 14, true);
        const out = [];
        for (let i = 0; i < count && i < 4096; i++) {
          const e = dirOff + 16 + i * 8;
          out.push({ id: dv.getUint32(e, true), target: dv.getUint32(e + 4, true) });
        }
        return out;
      };
      const RT_VERSION = 16;
      const typeEntry = entries(rsrcOff).find((e) => e.id === RT_VERSION);
      if (!typeEntry || !(typeEntry.target & 0x80000000)) return null;
      const nameEntry = entries(rsrcOff + (typeEntry.target & 0x7fffffff))[0];
      if (!nameEntry || !(nameEntry.target & 0x80000000)) return null;
      const langEntry = entries(rsrcOff + (nameEntry.target & 0x7fffffff))[0];
      if (!langEntry || (langEntry.target & 0x80000000)) return null;
      const dataEntryOff = rsrcOff + langEntry.target; // IMAGE_RESOURCE_DATA_ENTRY
      const dataOff = rvaToOffset(peMeta, dv.getUint32(dataEntryOff, true));
      const dataSize = dv.getUint32(dataEntryOff + 4, true);
      if (dataOff < 0) return null;

      const root = readVersionBlock(bytes, dv, dataOff, Math.min(dataOff + dataSize, bytes.length));
      if (!root || root.key !== 'VS_VERSION_INFO') return null;

      const info = {};
      for (const sfi of versionChildren(bytes, dv, root).filter((b) => b.key === 'StringFileInfo')) {
        for (const table of versionChildren(bytes, dv, sfi)) {
          for (const str of versionChildren(bytes, dv, table)) {
            if (VERSION_FIELDS.includes(str.key) && !(str.key in info)) {
              const value = readUtf16z(bytes, str.valueOff, str.end)[0].trim();
              if (value) info[str.key] = value;
            }
          }
        }
      }
      return Object.keys(info).length ? info : null;
    } catch (e) {
      return null;
    }
  }

  // Words that say nothing about *which* company it is - two unrelated
  // "... Software Ltd" names must not count as a match.
  const GENERIC_NAME_WORDS = new Set([
    'inc', 'incorporated', 'corp', 'corporation', 'company', 'ltd', 'limited', 'llc', 'llp',
    'gmbh', 'plc', 'srl', 'spa', 'pty', 'pte', 'the', 'and', 'software', 'technologies',
    'technology', 'systems', 'solutions', 'foundation', 'group', 'holdings', 'international',
    'labs', 'digital', 'global', 'services', 'network', 'networks', 'studio', 'studios',
    'games', 'project', 'team', 'development', 'computer', 'computers', 'data', 'media',
  ]);

  function nameTokens(name) {
    return (name || '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').split(' ')
      .filter((t) => t.length >= 3 && !GENERIC_NAME_WORDS.has(t));
  }

  // Browsers save a re-download as "setup (1).exe"; that's not a rename.
  function canonicalFileName(name) {
    return (name || '').toLowerCase().replace(/\.mui$/, '').replace(/ \(\d+\)(?=\.[^.]+$)/, '');
  }

  // Does the publisher the file claims (CompanyName) agree with who signed
  // it, and is the file still called what it was built as? A file claiming
  // "Microsoft Corporation" but signed by someone else, or a renamed tool
  // (OriginalFilename "psexec.exe" saved as "update.exe"), is a classic
  // disguise. "differs" is a prompt to review, not proof: a foundation
  // signing a project's builds (OpenJS Foundation / "Node.js") differs too.
  function publisherCheck(versionInfo, leaf, fileName) {
    const signer = leaf ? (leaf.subject.attrs.O || leaf.subject.cn) : null;
    const company = versionInfo && versionInfo.CompanyName;
    let status = 'no-company';
    if (company && signer) {
      const signerTokens = new Set(nameTokens(signer));
      const joined = (s) => nameTokens(s).join('');
      const shared = nameTokens(company).some((t) => signerTokens.has(t));
      const contained = joined(company) && joined(signer)
        && (joined(company).includes(joined(signer)) || joined(signer).includes(joined(company)));
      status = shared || contained ? 'match' : 'differs';
    }

    const original = versionInfo && versionInfo.OriginalFilename;
    let renamed = false;
    if (original && fileName) {
      const a = canonicalFileName(original);
      const b = canonicalFileName(fileName);
      const stem = (s) => s.replace(/\.[^.]+$/, '');
      renamed = a !== b && stem(a) !== stem(b);
    }
    return { status, company, signer, renamed, originalFilename: original };
  }

  // Recomputes the Authenticode "page hash" over the whole file, excluding
  // the 4-byte PE checksum, the 8-byte Certificate Table directory entry,
  // and the appended certificate table itself - exactly as signtool does
  // when it originally signs the file. If the file was modified after
  // signing, this will not match the digest embedded in the signature.
  async function computeAuthenticodeDigest(bytes, peMeta, algoName) {
    const { checksumOff, secDirEntryOff, secVA, secSize } = peMeta;
    const endOfRealContent = secSize > 0 ? secVA : bytes.length;
    const part1 = bytes.subarray(0, checksumOff);
    const part2 = bytes.subarray(checksumOff + 4, secDirEntryOff);
    const part3 = bytes.subarray(secDirEntryOff + 8, endOfRealContent);
    const combined = new Uint8Array(part1.length + part2.length + part3.length);
    combined.set(part1, 0);
    combined.set(part2, part1.length);
    combined.set(part3, part1.length + part2.length);
    const digest = await crypto.subtle.digest(algoName, combined);
    return bytesToHex(new Uint8Array(digest));
  }

  // ===================== MSI (OLE compound file) =====================

  // A .msi is not a PE: it's an OLE Compound File (a FAT-like filesystem in
  // a file), and its Authenticode signature is the raw PKCS#7 blob stored in
  // the hidden root stream "DigitalSignature" (no WIN_CERTIFICATE
  // header). Modern signtool also writes "MsiDigitalSignatureEx", a
  // prehash of the package metadata, which is folded into the file digest.

  const CFB_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  const CFB_MAX_REGULAR_SECTOR = 0xfffffffa;
  const CFB_NOSTREAM = 0xffffffff;
  const MSI_SIGNATURE_STREAM = 'DigitalSignature';
  const MSI_SIGNATURE_EX_STREAM = 'MsiDigitalSignatureEx';
  const DIGEST_BYTE_LENGTHS = { 'SHA-1': 20, 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 };

  function isCompoundFile(bytes) {
    return bytes.length >= 512 && CFB_MAGIC.every((b, i) => bytes[i] === b);
  }

  function concatBytes(parts) {
    let total = 0;
    for (const p of parts) total += p.length;
    const out = new Uint8Array(total);
    let pos = 0;
    for (const p of parts) {
      out.set(p, pos);
      pos += p.length;
    }
    return out;
  }

  function parseCompoundFile(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const sectorShift = dv.getUint16(0x1e, true);
    const miniShift = dv.getUint16(0x20, true);
    if (sectorShift !== 9 && sectorShift !== 12) throw new Error('Unsupported compound-file sector size');
    const sectorSize = 1 << sectorShift;
    const miniSectorSize = 1 << miniShift;
    const numFatSectors = dv.getUint32(0x2c, true);
    const dirStart = dv.getUint32(0x30, true);
    const miniCutoff = dv.getUint32(0x38, true);
    const miniFatStart = dv.getUint32(0x3c, true);
    const difatStart = dv.getUint32(0x44, true);
    const numDifat = dv.getUint32(0x48, true);
    const corrupt = () => new Error('Corrupt compound file');

    // Sector n lives at (n + 1) * sectorSize - the header takes the first sector.
    const sectorOffset = (n) => {
      const off = (n + 1) * sectorSize;
      if (n > CFB_MAX_REGULAR_SECTOR || off >= bytes.length) throw corrupt();
      return off;
    };

    // The FAT's own sector list: 109 entries in the header, then a chain of DIFAT sectors.
    const fatSectorIds = [];
    for (let i = 0; i < 109; i++) fatSectorIds.push(dv.getUint32(0x4c + i * 4, true));
    for (let s = difatStart, i = 0; i < numDifat && s <= CFB_MAX_REGULAR_SECTOR; i++) {
      const off = sectorOffset(s);
      for (let j = 0; j < sectorSize / 4 - 1; j++) fatSectorIds.push(dv.getUint32(off + j * 4, true));
      s = dv.getUint32(off + sectorSize - 4, true);
    }
    const perSector = sectorSize / 4;
    const fat = new Uint32Array(numFatSectors * perSector);
    fatSectorIds.slice(0, numFatSectors).forEach((sid, i) => {
      const off = sectorOffset(sid);
      for (let j = 0; j < perSector; j++) fat[i * perSector + j] = dv.getUint32(off + j * 4, true);
    });

    const readChain = (start) => {
      const parts = [];
      let s = start;
      for (let guard = 0; s <= CFB_MAX_REGULAR_SECTOR; guard++) {
        if (guard > fat.length || s >= fat.length) throw corrupt();
        const off = sectorOffset(s);
        parts.push(bytes.subarray(off, Math.min(off + sectorSize, bytes.length)));
        s = fat[s];
      }
      return concatBytes(parts);
    };

    const dirBytes = readChain(dirStart);
    const dirView = new DataView(dirBytes.buffer, dirBytes.byteOffset, dirBytes.byteLength);
    const entries = [];
    for (let o = 0; o + 128 <= dirBytes.length; o += 128) {
      const nameLen = Math.max(0, Math.min(dirView.getUint16(o + 0x40, true) - 2, 62)); // drop the UTF-16 terminator
      const nameRaw = dirBytes.subarray(o, o + nameLen);
      let name = '';
      for (let k = 0; k + 1 < nameLen; k += 2) name += String.fromCharCode(nameRaw[k] | (nameRaw[k + 1] << 8));
      // The size field is 64-bit, but 512-byte-sector files only use the low 32 bits.
      const sizeLo = dirView.getUint32(o + 0x78, true);
      const sizeHi = dirView.getUint32(o + 0x7c, true);
      entries.push({
        name, nameRaw,
        type: dirBytes[o + 0x42], // 1 storage, 2 stream, 5 root
        left: dirView.getUint32(o + 0x44, true),
        right: dirView.getUint32(o + 0x48, true),
        child: dirView.getUint32(o + 0x4c, true),
        clsid: dirBytes.subarray(o + 0x50, o + 0x60),
        start: dirView.getUint32(o + 0x74, true),
        size: sectorSize === 512 ? sizeLo : sizeHi * 4294967296 + sizeLo,
      });
    }
    const root = entries[0];
    if (!root || root.type !== 5) throw corrupt();

    // Streams smaller than the cutoff (4096) live in the "mini stream", a
    // container stream owned by the root entry, addressed via the mini FAT.
    const miniStream = root.size > 0 ? readChain(root.start).subarray(0, root.size) : new Uint8Array(0);
    let miniFat = new Uint32Array(0);
    if (miniFatStart <= CFB_MAX_REGULAR_SECTOR) {
      const mf = readChain(miniFatStart);
      miniFat = new Uint32Array(mf.length >> 2);
      const mfView = new DataView(mf.buffer, mf.byteOffset, mf.byteLength);
      for (let i = 0; i < miniFat.length; i++) miniFat[i] = mfView.getUint32(i * 4, true);
    }

    const readStream = (entry) => {
      let data;
      if (entry.size < miniCutoff) {
        const parts = [];
        let s = entry.start;
        for (let guard = 0; s <= CFB_MAX_REGULAR_SECTOR; guard++) {
          if (guard > miniFat.length || s >= miniFat.length) throw corrupt();
          parts.push(miniStream.subarray(s * miniSectorSize, (s + 1) * miniSectorSize));
          s = miniFat[s];
        }
        data = concatBytes(parts);
      } else {
        data = readChain(entry.start);
      }
      if (data.length < entry.size) throw corrupt();
      return data.subarray(0, entry.size);
    };

    // Children of a storage form a red-black tree via left/right siblings.
    const children = (entry) => {
      const out = [];
      const stack = [];
      const seen = new Set();
      let cur = entry.child;
      for (;;) {
        while (cur !== CFB_NOSTREAM && cur < entries.length && !seen.has(cur)) {
          seen.add(cur);
          stack.push(cur);
          cur = entries[cur].left;
        }
        if (!stack.length) break;
        const id = stack.pop();
        out.push(entries[id]);
        cur = entries[id].right;
      }
      return out;
    };

    const findRootStream = (name) => children(root).find((e) => e.type === 2 && e.name === name) || null;
    return { root, children, readStream, findRootStream };
  }

  // Human label from the root storage's CLSID: {000C1084-...} is a Windows
  // Installer package, {000C1086-...} a patch, {000C1082-...} a transform.
  function describeCompoundFile(root) {
    const c = root.clsid;
    if (c[1] === 0x10 && c[2] === 0x0c && c[3] === 0x00) {
      if (c[0] === 0x84) return 'MSI - Windows Installer package (OLE compound file)';
      if (c[0] === 0x86) return 'MSP - Windows Installer patch (OLE compound file)';
      if (c[0] === 0x82) return 'MST - Windows Installer transform (OLE compound file)';
    }
    return 'OLE compound file';
  }

  function compareNameBytes(a, b) {
    const x = a.nameRaw;
    const y = b.nameRaw;
    const n = Math.min(x.length, y.length);
    for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i] - y[i];
    return x.length - y.length;
  }

  // The MSI file digest, as reproduced against real signtool-signed packages:
  // [MsiDigitalSignatureEx bytes, if present] + every stream's contents in
  // the order given by comparing the raw UTF-16LE entry names (recursing into
  // sub-storages, and following each storage's children with its 16-byte
  // CLSID) + the root CLSID - excluding the two signature streams themselves.
  // Returns null when the digest can't be reproduced (e.g. the prehash in
  // MsiDigitalSignatureEx was made with a different hash algorithm).
  async function computeMsiDigest(cfb, algoName) {
    const chunks = [];
    const exEntry = cfb.findRootStream(MSI_SIGNATURE_EX_STREAM);
    if (exEntry) {
      const ex = cfb.readStream(exEntry);
      if (ex.length !== DIGEST_BYTE_LENGTHS[algoName]) return null;
      chunks.push(ex);
    }
    const walk = (storage) => {
      for (const child of cfb.children(storage).sort(compareNameBytes)) {
        if (child.type === 2) {
          if (child.name === MSI_SIGNATURE_STREAM || child.name === MSI_SIGNATURE_EX_STREAM) continue;
          chunks.push(cfb.readStream(child));
        } else if (child.type === 1) {
          walk(child);
          chunks.push(child.clsid);
        }
      }
    };
    walk(cfb.root);
    chunks.push(cfb.root.clsid);
    const digest = await crypto.subtle.digest(algoName, concatBytes(chunks));
    return bytesToHex(new Uint8Array(digest));
  }

  // ===================== Top-level entry point =====================

  // Builds one report.signatures[] entry for a single SignerInfo. Split out
  // from analyzeFile because a dual SHA-1/SHA-256 signed binary can encode
  // its second signature either as a second WIN_CERTIFICATE blob (the
  // standard `signtool sign /as` behavior, and the common case) or,
  // less commonly, as a second SignerInfo inside one blob's SignedData -
  // both need identical per-signature handling.
  // computeDigest(algoName) recomputes the file digest for whichever format
  // this is (PE page-hash or MSI stream-walk) - or resolves null when it
  // can't be reproduced, which shows up as "could not verify" rather than
  // ever being reported as tampering.
  async function buildSignatureEntry(signerInfo, pkcs7, computeDigest) {
    const leaf = signerInfo ? signerInfo.cert : null;

    let timestamp = null;
    if (signerInfo) {
      try {
        timestamp = await extractTimestamp(signerInfo, pkcs7.certsByKey);
      } catch (e) {
        timestamp = { type: 'unknown', time: null, signerCert: null, error: 'Could not parse timestamp: ' + e.message };
      }
    }

    let computedDigest = null;
    let digestMatch = null;
    if (pkcs7.fileDigestAlgorithm && WEBCRYPTO_HASH_NAMES.has(pkcs7.fileDigestAlgorithm)) {
      try {
        computedDigest = await computeDigest(pkcs7.fileDigestAlgorithm);
      } catch (e) {
        computedDigest = null;
      }
      if (computedDigest) {
        digestMatch = !!pkcs7.fileDigestHex && computedDigest.toLowerCase() === pkcs7.fileDigestHex.toLowerCase();
      }
    }

    const trustedTime = (timestamp && timestamp.time) || (signerInfo && signerInfo.signingTime) || null;
    let withinValidity = null;
    if (leaf && leaf.notBefore && leaf.notAfter && trustedTime) {
      withinValidity = trustedTime >= leaf.notBefore && trustedTime <= leaf.notAfter;
    }

    return {
      digestAlgorithm: pkcs7.fileDigestAlgorithm,
      embeddedDigest: pkcs7.fileDigestHex,
      computedDigest, digestMatch,
      leaf, chain: pkcs7.certs,
      signingTimeClaimed: signerInfo ? signerInfo.signingTime : null,
      programName: signerInfo ? signerInfo.programName : null,
      moreInfoUrl: signerInfo ? signerInfo.moreInfoUrl : null,
      timestamp, withinValidity,
    };
  }

  // Windows' own dual-signing convention (`signtool sign` then `signtool
  // sign /as` to append a second, e.g. SHA-256, signature to an already
  // SHA-1-signed PE) does NOT add a second WIN_CERTIFICATE blob or a
  // second SignerInfo alongside the first - it embeds the entire second
  // Authenticode signature (its own ContentInfo/SignedData, certs,
  // SignerInfo, even its own timestamp) as an unauthenticated attribute
  // (szOID_NESTED_SIGNATURE) ON the first SignerInfo. Recurse into it so
  // that's rendered as its own full signature too, not silently dropped.
  const NESTED_SIGNATURE_OID = '1.3.6.1.4.1.311.2.4.1';

  async function collectSignatures(pkcs7, computeDigest, results) {
    // Normally exactly one SignerInfo per blob - but handle the rare
    // multi-SignerInfo-in-one-blob encoding too, so a dual SHA-1/SHA-256
    // signature is never silently dropped no matter how it's encoded.
    const signerInfos = pkcs7.signerInfos.length ? pkcs7.signerInfos : [null];
    for (const signerInfo of signerInfos) {
      results.push(await buildSignatureEntry(signerInfo, pkcs7, computeDigest));

      const nested = signerInfo && signerInfo.unauthAttrs && signerInfo.unauthAttrs[NESTED_SIGNATURE_OID];
      if (nested) {
        for (const nestedAttrValue of nested) {
          try {
            const nestedPkcs7 = await parsePkcs7(nestedAttrValue.raw);
            await collectSignatures(nestedPkcs7, computeDigest, results);
          } catch (e) {
            results.push({ error: 'Failed to parse nested signature: ' + e.message });
          }
        }
      }
    }
  }

  async function analyzeFile(file) {
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    const fileSha256 = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));

    // fileType is 'PE' or 'MSI' once the file is recognized; architecture
    // doubles as the "Format" line shown in the report header.
    const report = {
      fileName: file.name, fileSize: bytes.length, fileSha256,
      fileType: null, architecture: null, signed: false, signatures: [], error: null,
    };

    if (isCompoundFile(bytes)) return analyzeMsi(bytes, report);

    let peMeta;
    try {
      peMeta = findPeCertBlobs(bytes);
    } catch (e) {
      report.error = e.message;
      return report;
    }
    report.fileType = 'PE';
    report.architecture = peMeta.pe32 ? 'PE32 (32-bit)' : 'PE32+ (64-bit)';
    report.versionInfo = parseVersionInfo(bytes, peMeta);

    if (!peMeta.blobs.length) return report;
    report.signed = true;

    const computeDigest = (algoName) => computeAuthenticodeDigest(bytes, peMeta, algoName);
    for (const blob of peMeta.blobs) {
      try {
        if (blob.certType !== 0x0002) {
          report.signatures.push({ error: `Unsupported certificate entry type 0x${blob.certType.toString(16)} (expected PKCS#7 Authenticode)` });
          continue;
        }

        const pkcs7 = await parsePkcs7(blob.der);
        await collectSignatures(pkcs7, computeDigest, report.signatures);
      } catch (e) {
        report.signatures.push({ error: 'Failed to parse this signature: ' + e.message });
      }
    }

    return report;
  }

  async function analyzeMsi(bytes, report) {
    let cfb;
    let sigEntry;
    try {
      cfb = parseCompoundFile(bytes);
      sigEntry = cfb.findRootStream(MSI_SIGNATURE_STREAM);
    } catch (e) {
      report.error = 'Could not read this file as a Windows Installer package: ' + e.message;
      return report;
    }
    report.fileType = 'MSI';
    report.architecture = describeCompoundFile(cfb.root);

    if (!sigEntry) return report;
    report.signed = true;

    // Digests are cached per algorithm - a dual-signed package asks for the same one twice.
    const cache = {};
    const computeDigest = (algoName) => (cache[algoName] = cache[algoName] || computeMsiDigest(cfb, algoName));
    try {
      const pkcs7 = await parsePkcs7(cfb.readStream(sigEntry));
      await collectSignatures(pkcs7, computeDigest, report.signatures);
    } catch (e) {
      report.signatures.push({ error: 'Failed to parse this signature: ' + e.message });
    }
    return report;
  }

  // ===================== Rendering =====================

  const COPY_ICON = '<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>';

  const BADGE_COLORS = {
    green: 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200',
    red: 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200',
    yellow: 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200',
    gray: 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200',
  };

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function fmtDate(d) {
    if (!d) return null;
    try {
      return d.toUTCString().replace('GMT', 'UTC');
    } catch (e) {
      return String(d);
    }
  }

  // Compact "12 Feb 2026" form for the concise summary card and CSV export.
  function fmtDateShort(d) {
    if (!d) return null;
    try {
      return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' });
    } catch (e) {
      return String(d);
    }
  }

  function badge(text, color) {
    return `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${BADGE_COLORS[color] || BADGE_COLORS.gray}">${text}</span>`;
  }

  function fieldRow(label, value, opts) {
    opts = opts || {};
    if (value === null || value === undefined || value === '') return '';
    const valueStr = String(value);
    const valueCls = opts.mono ? 'font-mono text-xs break-all' : 'text-sm';
    return `
      <div class="flex items-start justify-between gap-2">
        <div class="min-w-0 flex-1">
          <div class="text-xs text-gray-500 dark:text-gray-400">${escapeHtml(label)}</div>
          <div class="text-gray-900 dark:text-gray-100 ${valueCls}">${escapeHtml(valueStr)}</div>
        </div>
        <button type="button" class="copy-btn shrink-0 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 mt-4" data-copy="${escapeHtml(valueStr)}" title="Copy ${escapeHtml(label)}">${COPY_ICON}</button>
      </div>`;
  }

  function certCard(title, cert, opts) {
    opts = opts || {};
    if (!cert) {
      return `<div class="text-sm text-gray-500 dark:text-gray-400 italic">${escapeHtml(title)}: certificate not found among the signature's embedded certificates.</div>`;
    }
    const now = new Date();
    const expired = cert.notAfter && now > cert.notAfter;
    const notYetValid = cert.notBefore && now < cert.notBefore;
    let validityBadge = badge('✔️ Currently valid', 'green');
    if (expired) validityBadge = badge('⌛ Expired', opts.expiredIsFatal === false ? 'yellow' : 'red');
    else if (notYetValid) validityBadge = badge('⏳ Not yet valid', 'yellow');

    return `
      <div class="bg-gray-50 dark:bg-gray-900/40 rounded-md p-3 space-y-1">
        <div class="flex items-center justify-between flex-wrap gap-2 mb-1">
          <span class="text-sm font-semibold text-gray-900 dark:text-gray-100">${escapeHtml(title)}</span>
          ${validityBadge}
        </div>
        ${fieldRow('Subject (Common Name)', cert.subject.cn)}
        ${fieldRow('Subject (full DN)', cert.subject.string, { mono: true })}
        ${fieldRow('Issued by (CA)', cert.issuer.string, { mono: true })}
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-4">
          ${fieldRow('Valid from', fmtDate(cert.notBefore))}
          ${fieldRow('Valid to', fmtDate(cert.notAfter))}
        </div>
        ${fieldRow('Serial number', cert.serialHex, { mono: true })}
        ${fieldRow('Signature algorithm', cert.sigAlgorithm)}
        ${fieldRow('Public key', cert.publicKeyBits ? `${cert.publicKeyAlgorithm} ${cert.publicKeyBits}-bit` : cert.publicKeyAlgorithm)}
        ${cert.ekus && cert.ekus.length ? fieldRow('Extended key usage', cert.ekus.join(', ')) : ''}
        ${fieldRow('SHA-1 thumbprint', cert.thumbprintSha1, { mono: true })}
        ${fieldRow('SHA-256 thumbprint', cert.thumbprintSha256, { mono: true })}
      </div>`;
  }

  // ===================== CSV export =====================

  function csvCell(v) {
    if (v === null || v === undefined) return '';
    const s = String(v);
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  function buildCsvRows(report) {
    const rows = [[
      'Signature #', 'Role', 'Subject (CN)', 'Subject (full DN)', 'Issuer (CA, full DN)',
      'Serial number', 'Valid from', 'Valid to', 'SHA-1 thumbprint', 'SHA-256 thumbprint',
      'Signature algorithm', 'Public key', 'Extended key usage', 'Known abused certificate',
    ]];

    const addCertRow = (sigIndex, role, cert) => {
      if (!cert) return;
      const bad = findKnownBadCert(cert);
      rows.push([
        sigIndex, role, cert.subject.cn, cert.subject.string, cert.issuer.string, cert.serialHex,
        fmtDate(cert.notBefore) || '', fmtDate(cert.notAfter) || '',
        cert.thumbprintSha1, cert.thumbprintSha256, cert.sigAlgorithm,
        cert.publicKeyBits ? `${cert.publicKeyAlgorithm} ${cert.publicKeyBits}-bit` : cert.publicKeyAlgorithm,
        (cert.ekus || []).join('; '),
        bad ? `YES - ${bad.note}` : 'No',
      ]);
    };

    (report.signatures || []).forEach((sig, i) => {
      if (sig.error) {
        rows.push([i + 1, 'error', sig.error, '', '', '', '', '', '', '', '', '', '', '']);
        return;
      }
      addCertRow(i + 1, 'Signer', sig.leaf);
      (sig.chain || []).filter((c) => c !== sig.leaf).forEach((c) => addCertRow(i + 1, c.isCA ? 'CA' : 'Certificate', c));
      if (sig.timestamp && sig.timestamp.signerCert) addCertRow(i + 1, 'Timestamp Authority', sig.timestamp.signerCert);
    });

    return rows;
  }

  function rowsToCsv(rows) {
    return rows.map((r) => r.map(csvCell).join(',')).join('\r\n');
  }

  // btoa() only handles Latin-1, so route the (possibly non-ASCII, e.g.
  // accented issuer names) UTF-8 string through the classic escape trick.
  function toBase64Utf8(str) {
    return btoa(unescape(encodeURIComponent(str)));
  }

  function csvExportButton(report) {
    const csv = rowsToCsv(buildCsvRows(report));
    const safeName = (report.fileName || 'certificate').replace(/[^a-z0-9_.-]+/gi, '_');
    return `
      <button type="button" class="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-indigo-600 hover:bg-indigo-700 text-white rounded-md transition-colors" data-csv-b64="${toBase64Utf8(csv)}" data-csv-filename="${escapeHtml(safeName)}_certificates.csv">
        ⬇️ Export CSV
      </button>`;
  }

  // Mirrors the "Embedded Signatures" list in Windows' own Digital
  // Signature Details dialog (Name of signer / Digest algorithm /
  // Timestamp, one row per signature) - a single at-a-glance table for
  // dual SHA-1/SHA-256 signed files, so you don't have to scroll through
  // two separate "Signature N of 2" sections just to compare them. Each
  // row links down to its full section below via an anchor.
  function embeddedSignaturesTable(report) {
    if (!report.signatures || report.signatures.length < 2) return '';

    const rows = report.signatures.map((sig, i) => {
      if (sig.error) {
        return `
          <tr class="border-t border-gray-200 dark:border-gray-700">
            <td colspan="3" class="px-3 py-2 text-sm text-red-600 dark:text-red-400">Signature ${i + 1}: ${escapeHtml(sig.error)}</td>
          </tr>`;
      }
      const name = sig.leaf ? sig.leaf.subject.cn : 'Unknown';
      const ts = sig.timestamp && sig.timestamp.time ? fmtDateShort(sig.timestamp.time) : 'None';
      return `
        <tr class="border-t border-gray-200 dark:border-gray-700">
          <td class="px-3 py-2 text-sm text-gray-900 dark:text-gray-100">
            <a href="#digicert-sig-${i}" class="hover:underline hover:text-indigo-600 dark:hover:text-indigo-400">${escapeHtml(name)}</a>
          </td>
          <td class="px-3 py-2 text-sm text-gray-900 dark:text-gray-100">${escapeHtml(sig.digestAlgorithm || 'unknown')}</td>
          <td class="px-3 py-2 text-sm text-gray-900 dark:text-gray-100">${escapeHtml(ts)}</td>
        </tr>`;
    }).join('');

    return `
      <div class="mb-4 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
        <p class="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400 px-3 pt-2">Embedded Signatures</p>
        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead>
              <tr class="text-xs text-gray-500 dark:text-gray-400">
                <th class="px-3 py-1.5 font-medium">Name of signer</th>
                <th class="px-3 py-1.5 font-medium">Digest algorithm</th>
                <th class="px-3 py-1.5 font-medium">Timestamp</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>`;
  }

  // Short, scannable "Cert Information" block: who signed it, how long it's
  // valid, which CA issued it, and whether/when it was countersigned -
  // everything else lives in the collapsible "Full details" below.
  // Plain-text summaries behind the two one-click copy buttons. A cert or
  // TSA name can be missing its CN (subject made of O/OU only), so fall back
  // to the full DN rather than printing nothing.
  function nameOf(dn) {
    return dn ? dn.cn || dn.string || 'Unknown' : 'Unknown';
  }

  // "Copy certificate summary" copies both sections (signer cert, then its
  // timestamp); "Copy timestamp summary" copies just the second one.
  function certSummaryText(sig) {
    const leaf = sig.leaf;
    return [
      'Certificate Information',
      `Name of signer: ${leaf ? nameOf(leaf.subject) : 'Unknown'}`,
      `CA: ${leaf ? nameOf(leaf.issuer) : 'Unknown'}`,
      `Valid from: ${(leaf && fmtDateShort(leaf.notBefore)) || 'Unknown'}`,
      `Valid to: ${(leaf && fmtDateShort(leaf.notAfter)) || 'Unknown'}`,
      '',
      timestampSummaryText(sig.timestamp),
    ].join('\n');
  }

  function timestampSummaryText(ts) {
    if (!ts || !ts.time) {
      return ['Timestamp Information', ts && ts.error ? `Unreadable: ${ts.error}` : 'None'].join('\n');
    }
    const tsa = ts.signerCert;
    return [
      'Timestamp Information',
      `Timestamped at: ${fmtDate(ts.time) || 'Unknown'}`,
      `Name of signer: ${tsa ? nameOf(tsa.subject) : 'Unknown'}`,
      `CA: ${tsa ? nameOf(tsa.issuer) : 'Unknown'}`,
      `Valid from: ${(tsa && fmtDateShort(tsa.notBefore)) || 'Unknown'}`,
      `Valid to: ${(tsa && fmtDateShort(tsa.notAfter)) || 'Unknown'}`,
    ].join('\n');
  }

  // Clicks are handled by the delegated [data-copy] listener in index.html.
  // Newlines are entity-encoded so the multi-line text survives the attribute.
  function copySummaryButton(text, label) {
    return `<button type="button" data-copy="${escapeHtml(text).replace(/\n/g, '&#10;')}" title="${escapeHtml(label)}" class="shrink-0 inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium bg-white dark:bg-gray-800 text-indigo-700 dark:text-indigo-300 border border-indigo-300 dark:border-indigo-700 rounded-md hover:bg-indigo-100 dark:hover:bg-indigo-900 transition-colors">📋 ${escapeHtml(label)}</button>`;
  }

  // On-demand OCSP/CRL check - the browser can't fetch CA endpoints itself
  // (CORS), so the delegated [data-revocation] listener in index.html posts
  // this payload to /api/cert-revocation. Everything it needs rides in the
  // attribute so it also works on a report restored from sessionStorage.
  // `refTime` is when the signature was made (the timestamp), which decides
  // how bad a revocation is - see renderRevocation().
  function revocationButton(cert, candidateIssuers, refTime) {
    if (!cert || !cert.derB64) return '';
    const issuer = (candidateIssuers || []).find((c) => c !== cert && c.subject.string === cert.issuer.string);
    const payload = {
      leaf_der_b64: cert.derB64,
      issuer_der_b64: issuer ? issuer.derB64 : null,
      ref_time: refTime ? refTime.toISOString() : null,
      expired: !!(cert.notAfter && new Date() > cert.notAfter),
    };
    return `
      <div class="pt-1">
        <button type="button" data-revocation="${escapeHtml(JSON.stringify(payload))}" class="text-xs px-2 py-1 bg-white dark:bg-gray-800 text-indigo-700 dark:text-indigo-300 border border-indigo-300 dark:border-indigo-700 rounded hover:bg-indigo-100 dark:hover:bg-indigo-900">🛡️ Check revocation (OCSP/CRL)</button>
        <div class="revocation-result text-sm mt-1"></div>
      </div>`;
  }

  const SEVERE_REVOCATION_REASONS = ['keyCompromise', 'cACompromise', 'aACompromise', 'unspecified'];

  // Microsoft's rule for timestamped code: a revocation dated *after* the
  // signature's timestamp doesn't invalidate it - unless the key was
  // compromised (or no reason was given), since then the timestamp itself
  // can't be trusted to predate the compromise.
  function renderRevocation(result, ctx) {
    const reason = result.reason || 'unspecified';
    const via = result.method ? ` via ${escapeHtml(result.method)}` : '';
    if (result.status === 'good') {
      const caveat = ctx.expired
        ? '<p class="text-xs text-gray-500 dark:text-gray-400">The certificate has expired; CAs often stop listing expired certificates, so this is weaker evidence.</p>'
        : '';
      return `${badge(`✔️ Not revoked${via}`, 'green')}${caveat}`;
    }
    if (result.status === 'revoked') {
      const revokedAt = result.revoked_at ? new Date(result.revoked_at) : null;
      const refTime = ctx.ref_time ? new Date(ctx.ref_time) : null;
      const afterSigning = revokedAt && refTime && revokedAt > refTime;
      const when = revokedAt ? fmtDateShort(revokedAt) : 'unknown date';
      if (afterSigning && !SEVERE_REVOCATION_REASONS.includes(reason)) {
        return `${badge(`⚠️ Revoked ${escapeHtml(when)} (${escapeHtml(reason)})`, 'yellow')}
          <p class="text-xs text-gray-600 dark:text-gray-400">Revoked after this file was timestamped (${escapeHtml(fmtDateShort(refTime))}), for a non-security reason, so the signature is still treated as valid.</p>`;
      }
      return `${badge(`🚨 Revoked ${escapeHtml(when)} (${escapeHtml(reason)})`, 'red')}
        <p class="text-xs text-red-700 dark:text-red-300">The CA has withdrawn this certificate${SEVERE_REVOCATION_REASONS.includes(reason) && reason !== 'unspecified' ? ' because its key was compromised' : ''}. Do not trust this signature.</p>`;
    }
    const expiredNote = ctx.expired ? ' CAs often stop publishing revocation status for expired certificates.' : '';
    return `${badge('❓ Status unknown', 'gray')}<p class="text-xs text-gray-600 dark:text-gray-400">${escapeHtml(result.note || '')}${expiredNote}</p>`;
  }

  // Same look as the Cert Information card, for the timestamp: when it was
  // countersigned, by which timestamp authority, and that authority's own CA
  // and expiry. The full TSA certificate is still under "More details".
  function timestampCard(sig) {
    const ts = sig.timestamp;
    const shell = (badgeHtml, body, copyHtml) => `
      <div class="bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800 rounded-md p-3 space-y-1">
        <div class="flex items-center justify-between gap-2 flex-wrap">
          <p class="text-xs font-semibold uppercase tracking-wide text-indigo-700 dark:text-indigo-300">Timestamp Information</p>
          <div class="flex items-center gap-2 flex-wrap">${badgeHtml}${copyHtml || ''}</div>
        </div>
        ${body}
      </div>`;
    const line = (label, value) => `<p class="text-sm text-gray-900 dark:text-gray-100"><strong>${label}:</strong> ${escapeHtml(value)}</p>`;

    if (ts && ts.time) {
      const tsa = ts.signerCert;
      const status = sig.withinValidity === false
        ? badge('⚠️ Outside cert validity', 'red')
        : badge('✔️ Timestamped', 'green');
      const type = ts.type === 'rfc3161' ? 'RFC 3161' : 'legacy Authenticode';
      return shell(status, [
        line('Timestamped at', fmtDate(ts.time)),
        line('Authority (TSA)', tsa ? nameOf(tsa.subject) : 'Unknown'),
        line('CA', tsa ? nameOf(tsa.issuer) : 'Unknown'),
        line('Valid to', (tsa && fmtDateShort(tsa.notAfter)) || 'Unknown'),
        line('Type', type),
        revocationButton(tsa, (ts.certs || []).concat(sig.chain || []), ts.time),
      ].join(''), copySummaryButton(timestampSummaryText(ts), 'Copy timestamp summary'));
    }
    if (ts && ts.error) {
      return shell(badge('⚠️ Unreadable', 'yellow'), line('Problem', ts.error));
    }
    return shell(badge('⚠️ None', 'yellow'),
      '<p class="text-sm text-gray-900 dark:text-gray-100">No trusted timestamp - this signature can’t be trusted once the signing certificate expires.</p>');
  }

  function publisherLines(pub) {
    if (!pub) return '';
    const row = (html) => `<p class="text-sm text-gray-900 dark:text-gray-100"><strong>Publisher:</strong> ${html}</p>`;
    let html;
    if (pub.status === 'match') {
      html = row(`✅ Matches signer <span class="text-xs text-gray-500 dark:text-gray-400">(file says “${escapeHtml(pub.company)}”)</span>`);
    } else if (pub.status === 'differs') {
      html = row(`⚠️ File says “${escapeHtml(pub.company)}”, signed by “${escapeHtml(pub.signer)}”`)
        + '<p class="text-xs text-gray-500 dark:text-gray-400">Sometimes legitimate (e.g. a foundation signing a project’s builds), but a classic disguise - check the signer is who you expect.</p>';
    } else {
      html = row('<span class="text-gray-500 dark:text-gray-400">No company name in the file’s version info</span>');
    }
    if (pub.renamed) {
      html += `<p class="text-sm text-gray-900 dark:text-gray-100"><strong>File name:</strong> ⚠️ Renamed - built as “${escapeHtml(pub.originalFilename)}”</p>`;
    }
    return html;
  }

  function conciseCard(sig, badMatch, pub) {
    const leaf = sig.leaf;
    const now = new Date();
    const expired = leaf && leaf.notAfter && now > leaf.notAfter;

    let signerBadge;
    if (badMatch) signerBadge = badge('🚨 Known abused cert', 'red');
    else if (!leaf) signerBadge = badge('⚠️ Unresolved', 'yellow');
    else if (expired) signerBadge = badge('⌛ Expired', 'yellow');
    else signerBadge = badge('✔️ Valid', 'green');

    const validStr = leaf && leaf.notBefore && leaf.notAfter
      ? `${fmtDateShort(leaf.notBefore)} – ${fmtDateShort(leaf.notAfter)}`
      : 'Unknown';

    const integrityLabel = sig.digestMatch === true ? '✅ Matches file'
      : sig.digestMatch === false ? '❌ MISMATCH - file changed since signing'
        : '⚠️ Unverified';

    return `
      <div class="bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800 rounded-md p-3 space-y-1">
        <div class="flex items-center justify-between gap-2 flex-wrap">
          <p class="text-xs font-semibold uppercase tracking-wide text-indigo-700 dark:text-indigo-300">Cert Information</p>
          <div class="flex items-center gap-2 flex-wrap">${signerBadge}${copySummaryButton(certSummaryText(sig), 'Copy certificate summary')}</div>
        </div>
        <p class="text-sm text-gray-900 dark:text-gray-100"><strong>Signer:</strong> ${escapeHtml(leaf ? nameOf(leaf.subject) : 'Unknown')}</p>
        <p class="text-sm text-gray-900 dark:text-gray-100"><strong>Valid:</strong> ${escapeHtml(validStr)}</p>
        <p class="text-sm text-gray-900 dark:text-gray-100"><strong>CA:</strong> ${escapeHtml(leaf ? nameOf(leaf.issuer) : 'Unknown')}</p>
        <p class="text-sm text-gray-900 dark:text-gray-100 pt-1 mt-1 border-t border-indigo-200 dark:border-indigo-800"><strong>Integrity:</strong> ${integrityLabel}</p>
        ${publisherLines(pub)}
        ${revocationButton(leaf, sig.chain, sig.timestamp && sig.timestamp.time)}
      </div>`;
  }

  function knownBadBanner(badMatch) {
    if (!badMatch) return '';
    return `
      <div class="rounded-md p-3 bg-red-50 dark:bg-red-900/30 border-2 border-red-400 dark:border-red-700 text-sm text-red-900 dark:text-red-200">
        🚨 <strong>Known abused certificate</strong> — this signer's certificate serial number matches a publicly documented leaked or stolen code-signing certificate: ${escapeHtml(badMatch.note)}.
        ${badMatch.ref ? `<a href="${escapeHtml(badMatch.ref)}" target="_blank" rel="noopener" class="underline">Source</a>.` : ''}
        Do not trust this signature.
      </div>`;
  }

  function renderSignature(sig, index, total, report) {
    if (sig.error) {
      return `
        <div id="digicert-sig-${index}" class="border border-red-200 dark:border-red-800 rounded-lg p-4 bg-red-50 dark:bg-red-900/30">
          <p class="text-sm text-red-700 dark:text-red-300"><strong>Signature ${index + 1}:</strong> ${escapeHtml(sig.error)}</p>
        </div>`;
    }

    const badMatch = findKnownBadCert(sig.leaf);

    let integrityBanner;
    if (sig.digestMatch === true) {
      integrityBanner = `<div class="rounded-md p-3 bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800 text-sm text-green-800 dark:text-green-200">✅ <strong>File integrity verified</strong> — the recomputed Authenticode hash matches the hash embedded in the signature. Nothing in the signed portions of the file has changed since it was signed.</div>`;
    } else if (sig.digestMatch === false) {
      integrityBanner = `<div class="rounded-md p-3 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-sm text-red-800 dark:text-red-200">❌ <strong>Hash mismatch</strong> — the file's current contents do not match the hash embedded in the signature. The file was modified after signing, or the signature is otherwise invalid. Treat it as untrusted.</div>`;
    } else {
      integrityBanner = `<div class="rounded-md p-3 bg-gray-50 dark:bg-gray-900/40 border border-gray-200 dark:border-gray-700 text-sm text-gray-600 dark:text-gray-400">⚠️ Could not verify file integrity (digest algorithm: ${escapeHtml(sig.digestAlgorithm || 'unknown')}).</div>`;
    }

    let timestampBlock;
    if (sig.timestamp && sig.timestamp.time) {
      const withinBadge = sig.withinValidity === true
        ? badge('✔️ Signed within cert validity', 'green')
        : sig.withinValidity === false
          ? badge('⚠️ Signed outside cert validity', 'red')
          : '';
      timestampBlock = `
        <div class="space-y-2">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <span class="text-sm font-semibold text-gray-900 dark:text-gray-100">🕒 Trusted timestamp (${sig.timestamp.type === 'rfc3161' ? 'RFC 3161' : 'legacy Authenticode'})</span>
            ${withinBadge}
          </div>
          ${fieldRow('Timestamped at', fmtDate(sig.timestamp.time))}
          <p class="text-xs text-gray-500 dark:text-gray-400">A trusted timestamp lets this signature remain valid even after the signing certificate above expires.</p>
          ${sig.timestamp.signerCert ? certCard('Timestamp Authority certificate', sig.timestamp.signerCert, { expiredIsFatal: false }) : ''}
        </div>`;
    } else if (sig.timestamp && sig.timestamp.error) {
      timestampBlock = `<div class="text-sm text-yellow-700 dark:text-yellow-300">⚠️ A timestamp attribute is present but could not be parsed: ${escapeHtml(sig.timestamp.error)}</div>`;
    } else {
      timestampBlock = `<div class="text-sm text-yellow-700 dark:text-yellow-300">⚠️ No trusted timestamp found. Once the signing certificate expires, this signature will no longer be treated as valid.</div>`;
    }

    const chainCerts = (sig.chain || []).filter((c) => c !== sig.leaf);

    return `
      <div id="digicert-sig-${index}" class="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden scroll-mt-4">
        <div class="bg-indigo-600 text-white px-4 py-2.5">
          <span class="font-semibold text-sm">✍️ Signature ${index + 1}${total > 1 ? ` of ${total}` : ''} — ${escapeHtml(sig.digestAlgorithm || 'unknown')} digest</span>
        </div>
        <div class="p-4 space-y-4">
          ${conciseCard(sig, badMatch, report.fileType === 'PE' ? publisherCheck(report.versionInfo, sig.leaf, report.fileName) : null)}
          ${timestampCard(sig)}
          ${knownBadBanner(badMatch)}
          <details class="group" open>
            <summary class="cursor-pointer text-sm font-semibold text-gray-700 dark:text-gray-300 select-none">More details ▾</summary>
            <div class="mt-3 space-y-4">
              ${integrityBanner}
              ${sig.programName || sig.moreInfoUrl ? `
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-4">
                ${fieldRow('Program name (self-declared by signer)', sig.programName)}
                ${fieldRow('More info URL (self-declared by signer)', sig.moreInfoUrl)}
              </div>` : ''}
              ${certCard('Signer (leaf certificate)', sig.leaf)}
              ${sig.signingTimeClaimed ? fieldRow('Self-declared signing time (not from a timestamp authority)', fmtDate(sig.signingTimeClaimed)) : ''}
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-4">
                ${fieldRow('Embedded file digest', sig.embeddedDigest, { mono: true })}
                ${fieldRow('Recomputed file digest', sig.computedDigest, { mono: true })}
              </div>
              ${timestampBlock}
              ${chainCerts.length ? `
              <div>
                <p class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">🔗 Issuing chain (${chainCerts.length} more certificate${chainCerts.length === 1 ? '' : 's'})</p>
                <div class="space-y-2">
                  ${chainCerts.map((c) => certCard(c.isCA ? 'CA certificate' : 'Certificate', c, { expiredIsFatal: false })).join('')}
                </div>
              </div>` : ''}
            </div>
          </details>
        </div>
      </div>`;
  }

  function renderReport(report) {
    const hasParsedCerts = (report.signatures || []).some((s) => s.leaf || (s.chain && s.chain.length) || (s.timestamp && s.timestamp.signerCert));

    const parts = [];
    parts.push(`
      <div class="bg-gray-50 dark:bg-gray-900/40 rounded-lg p-4 mb-4 space-y-1">
        <div class="flex items-center justify-between flex-wrap gap-2">
          <span class="text-sm font-semibold text-gray-900 dark:text-gray-100">📄 ${escapeHtml(report.fileName)}</span>
          <div class="flex items-center gap-2">
            ${report.signed ? badge('✔️ Signed', 'green') : badge(report.fileType ? '⚠️ Not signed' : '❌ Unsupported file', report.fileType ? 'yellow' : 'gray')}
            ${hasParsedCerts ? csvExportButton(report) : ''}
          </div>
        </div>
        ${fieldRow('File size', `${report.fileSize.toLocaleString()} bytes`)}
        ${report.architecture ? fieldRow('Format', report.architecture) : ''}
        ${fieldRow('File SHA-256 (whole file)', report.fileSha256, { mono: true })}
      </div>`);

    // What the file says about itself (Properties > Details) - self-declared
    // by whoever built it, so compared against the signer in each signature.
    const vi = report.versionInfo;
    if (vi) {
      parts.push(`
      <div class="bg-gray-50 dark:bg-gray-900/40 rounded-lg p-4 mb-4">
        <p class="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400 mb-1">File Information (self-declared)</p>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-4">
          ${fieldRow('Company', vi.CompanyName)}
          ${fieldRow('Product', vi.ProductName)}
          ${fieldRow('Description', vi.FileDescription)}
          ${fieldRow('Original file name', vi.OriginalFilename)}
          ${fieldRow('File version', vi.FileVersion)}
          ${fieldRow('Copyright', vi.LegalCopyright)}
        </div>
      </div>`);
    }

    if (report.error) {
      parts.push(`<div class="text-sm text-red-600 dark:text-red-400">${escapeHtml(report.error)}</div>`);
      return parts.join('');
    }

    if (!report.signed) {
      parts.push(report.fileType === 'MSI'
        ? `<div class="text-sm text-gray-600 dark:text-gray-400">This installer has no embedded digital signature.</div>`
        : `<div class="text-sm text-gray-600 dark:text-gray-400">This file has no embedded Authenticode signature. (Some Windows system files are "catalog-signed" instead — signed via a separate .cat file rather than embedded in the binary — and will also show as unsigned here.)</div>`);
      return parts.join('');
    }

    parts.push(embeddedSignaturesTable(report));

    parts.push('<div class="space-y-4">');
    report.signatures.forEach((sig, i) => parts.push(renderSignature(sig, i, report.signatures.length, report)));
    parts.push('</div>');

    return parts.join('');
  }

  global.AuthenticodeParser = { analyzeFile, renderReport, renderRevocation };
})(window);
