/*
 * Client-side Authenticode / PE digital-signature parser + renderer.
 *
 * Everything here runs entirely in the browser. The selected .exe/.dll never
 * leaves the machine - only the parsed certificate/signature metadata is
 * rendered to the page, mirroring the "hashed locally" promise made
 * elsewhere in this app for the Single Lookup file input.
 *
 * Covers:
 *   - Locating the WIN_CERTIFICATE table in the PE (supports dual SHA-1 +
 *     SHA-256 signing, i.e. multiple embedded signature blobs)
 *   - Parsing the embedded PKCS#7/Authenticode SignedData structure with a
 *     minimal hand-rolled DER reader (no external dependencies)
 *   - Walking the certificate chain (signer -> intermediates -> root)
 *   - Extracting the RFC3161 (or legacy) counter-signature timestamp
 *   - Recomputing the Authenticode page-hash and comparing it to the
 *     digest embedded in the signature, to flag tampering after signing
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

  function decodeExtensions(extensionsNode) {
    const ekus = [];
    let isCA = null;
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
        }
      }
    } catch (e) {
      /* best-effort */
    }
    return { ekus, isCA };
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

    const { ekus, isCA } = extensionsNode ? decodeExtensions(extensionsNode) : { ekus: [], isCA: null };

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
      ekus, isCA,
      thumbprintSha1: thumbSha1,
      thumbprintSha256: thumbSha256,
      issuerAndSerialKey: issuer.string + '|' + serialHex,
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
      };
    }

    return null;
  }

  // ===================== PE / WIN_CERTIFICATE extraction =====================

  function findPeCertBlobs(bytes) {
    if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) {
      throw new Error('Not a PE file (missing "MZ" header) - select an .exe, .dll or similar');
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

    return { pe32, checksumOff, secDirEntryOff, secVA, secSize, blobs };
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

  // ===================== Top-level entry point =====================

  // Builds one report.signatures[] entry for a single SignerInfo. Split out
  // from analyzeFile because a dual SHA-1/SHA-256 signed binary can encode
  // its second signature either as a second WIN_CERTIFICATE blob (the
  // standard `signtool sign /as` behavior, and the common case) or,
  // less commonly, as a second SignerInfo inside one blob's SignedData -
  // both need identical per-signature handling.
  async function buildSignatureEntry(signerInfo, pkcs7, bytes, peMeta) {
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
      computedDigest = await computeAuthenticodeDigest(bytes, peMeta, pkcs7.fileDigestAlgorithm);
      digestMatch = !!pkcs7.fileDigestHex && computedDigest.toLowerCase() === pkcs7.fileDigestHex.toLowerCase();
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

  async function analyzeFile(file) {
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    const fileSha256 = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));

    const report = {
      fileName: file.name, fileSize: bytes.length, fileSha256,
      isPE: false, architecture: null, signed: false, signatures: [], error: null,
    };

    let peMeta;
    try {
      peMeta = findPeCertBlobs(bytes);
    } catch (e) {
      report.error = e.message;
      return report;
    }
    report.isPE = true;
    report.architecture = peMeta.pe32 ? 'PE32 (32-bit)' : 'PE32+ (64-bit)';

    if (!peMeta.blobs.length) return report;
    report.signed = true;

    for (const blob of peMeta.blobs) {
      try {
        if (blob.certType !== 0x0002) {
          report.signatures.push({ error: `Unsupported certificate entry type 0x${blob.certType.toString(16)} (expected PKCS#7 Authenticode)` });
          continue;
        }

        const pkcs7 = await parsePkcs7(blob.der);
        // Normally exactly one SignerInfo per blob - but handle the rare
        // multi-SignerInfo-in-one-blob encoding too, so a dual SHA-1/
        // SHA-256 signature is never silently dropped either way.
        const signerInfos = pkcs7.signerInfos.length ? pkcs7.signerInfos : [null];
        for (const signerInfo of signerInfos) {
          report.signatures.push(await buildSignatureEntry(signerInfo, pkcs7, bytes, peMeta));
        }
      } catch (e) {
        report.signatures.push({ error: 'Failed to parse this signature: ' + e.message });
      }
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

  // Short, scannable "Cert Information" block: who signed it, how long it's
  // valid, which CA issued it, and whether/when it was countersigned -
  // everything else lives in the collapsible "Full details" below.
  function conciseCard(sig, badMatch) {
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

    const tsLabel = sig.timestamp && sig.timestamp.time
      ? `${sig.timestamp.signerCert ? sig.timestamp.signerCert.subject.cn + ', ' : ''}${fmtDateShort(sig.timestamp.time)}`
      : 'None (signature can’t be trusted once the cert above expires)';

    const integrityLabel = sig.digestMatch === true ? '✅ Matches file'
      : sig.digestMatch === false ? '❌ MISMATCH - file changed since signing'
        : '⚠️ Unverified';

    return `
      <div class="bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800 rounded-md p-3 space-y-1">
        <div class="flex items-center justify-between gap-2 flex-wrap">
          <p class="text-xs font-semibold uppercase tracking-wide text-indigo-700 dark:text-indigo-300">Cert Information</p>
          ${signerBadge}
        </div>
        <p class="text-sm text-gray-900 dark:text-gray-100"><strong>Signer:</strong> ${escapeHtml(leaf ? leaf.subject.cn : 'Unknown')}</p>
        <p class="text-sm text-gray-900 dark:text-gray-100"><strong>Valid:</strong> ${escapeHtml(validStr)}</p>
        <p class="text-sm text-gray-900 dark:text-gray-100"><strong>CA:</strong> ${escapeHtml(leaf ? leaf.issuer.cn : 'Unknown')}</p>
        <p class="text-sm text-gray-900 dark:text-gray-100 pt-1 mt-1 border-t border-indigo-200 dark:border-indigo-800"><strong>Countersign:</strong> ${escapeHtml(tsLabel)}</p>
        <p class="text-sm text-gray-900 dark:text-gray-100"><strong>Integrity:</strong> ${integrityLabel}</p>
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

  function renderSignature(sig, index, total) {
    if (sig.error) {
      return `
        <div class="border border-red-200 dark:border-red-800 rounded-lg p-4 bg-red-50 dark:bg-red-900/30">
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
      <div class="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
        <div class="bg-indigo-600 text-white px-4 py-2.5">
          <span class="font-semibold text-sm">✍️ Signature ${index + 1}${total > 1 ? ` of ${total}` : ''} — ${escapeHtml(sig.digestAlgorithm || 'unknown')} digest</span>
        </div>
        <div class="p-4 space-y-4">
          ${conciseCard(sig, badMatch)}
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
            ${report.signed ? badge('✔️ Signed', 'green') : badge(report.isPE ? '⚠️ Not signed' : '❌ Not a PE file', report.isPE ? 'yellow' : 'gray')}
            ${hasParsedCerts ? csvExportButton(report) : ''}
          </div>
        </div>
        ${fieldRow('File size', `${report.fileSize.toLocaleString()} bytes`)}
        ${report.architecture ? fieldRow('Format', report.architecture) : ''}
        ${fieldRow('File SHA-256 (whole file)', report.fileSha256, { mono: true })}
      </div>`);

    if (report.error) {
      parts.push(`<div class="text-sm text-red-600 dark:text-red-400">${escapeHtml(report.error)}</div>`);
      return parts.join('');
    }

    if (!report.signed) {
      parts.push(`<div class="text-sm text-gray-600 dark:text-gray-400">This file has no embedded Authenticode signature. (Some Windows system files are "catalog-signed" instead — signed via a separate .cat file rather than embedded in the binary — and will also show as unsigned here.)</div>`);
      return parts.join('');
    }

    parts.push('<div class="space-y-4">');
    report.signatures.forEach((sig, i) => parts.push(renderSignature(sig, i, report.signatures.length)));
    parts.push('</div>');

    return parts.join('');
  }

  global.AuthenticodeParser = { analyzeFile, renderReport };
})(window);
