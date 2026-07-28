---
title: "SLH-DSA for JOSE and COSE"
category: std

docname: draft-ietf-cose-sphincs-plus-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "CBOR Object Signing and Encryption"
keyword:
 - JOSE
 - COSE
 - PQC
 - SPHINCS+
 - SLH-DSA

venue:
  group: "CBOR Object Signing and Encryption"
  type: "Working Group"
  mail: "cose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cose/"
  github: "cose-wg/draft-ietf-cose-sphincs-plus"
  latest: "https://cose-wg.github.io/draft-ietf-cose-sphincs-plus/draft-ietf-cose-sphincs-plus.html"

author:
 -
    fullname: "Michael Prorock"
    organization: mesur.io
    email: "mprorock@mesur.io"
 -
    fullname: "Orie Steele"
    organization: Tradeverifyd
    email: "orie@or13.io"
 -
    fullname: Hannes Tschofenig
    organization: University of the Bundeswehr Munich
    abbrev: UniBw M.
    city: Neubiberg
    country: Germany
    code: 85577
    email: hannes.tschofenig@gmx.net

contributor:
 -
    fullname: "Rafael Misoczki"
    organization: Meta
    email: "rafam@meta.com"
 -
    fullname: "Michael Osborne"
    organization: IBM
    email: "osb@zurich.ibm.com"
 -
    fullname: "Christine Cloostermans"
    organization: NXP
    email: "christine.cloostermans@nxp.com"

normative:
  RFC7515: JWS
  RFC7517: JWK
  RFC7518: JWA
  RFC9052: COSE
  RFC9053: COSE-Alg
  RFC9054: COSE-Header-Parameters
  RFC9964: ML-DSA
  FIPS-205:
    title: "Stateless Hash-Based Digital Signature Standard"
    target: https://doi.org/10.6028/NIST.FIPS.205

informative:
  IANA.jose: IANA.jose
  IANA.cose: IANA.cose
  I-D.ietf-cose-hash-envelope:
  RFC9814:
  RFC9909:

---

--- abstract

Digital signatures are used within JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE) to protect the integrity and authenticity of messages, such as JSON Web Signatures and signed COSE structures. This document specifies JOSE and COSE serializations for the Stateless Hash-Based Digital Signature Standard (SLH-DSA), a Post-Quantum Cryptography (PQC) digital signature scheme defined in US NIST FIPS 205. The conventions for the associated algorithm identifiers, signatures, public keys, and private keys are also specified.


--- middle

# Introduction

This document specifies JSON Object Signing and Encryption (JOSE) {{-JWS}} and CBOR Object Signing and Encryption (COSE) {{-COSE}} serializations for the Stateless Hash-Based Digital Signature Standard (SLH-DSA), a Post-Quantum Cryptography (PQC) based digital signature scheme standardized in {{FIPS-205}}.

This document builds on the Algorithm Key Pair (AKP) type, as defined in {{-ML-DSA}}. The AKP type enables flexible representation of keys used across different post-quantum cryptographic algorithms, including SLH-DSA.

# Terminology

{::boilerplate bcp14-tagged}

# The SLH-DSA Algorithm Family

This document registers two SLH-DSA parameter sets at NIST security category 1.

This document introduces the registration of the following algorithms in {{-IANA.jose}}:

| Name       | alg | Description |
|-------------|------|-------------|
| SLH-DSA-SHA2-128s  | SLH-DSA-SHA2-128s     | JSON Web Signature Algorithm for SLH-DSA-SHA2-128s |
| SLH-DSA-SHAKE-128s | SLH-DSA-SHAKE-128s    | JSON Web Signature Algorithm for SLH-DSA-SHAKE-128s |
{: #jose-algorithms align="left" title="JOSE Algorithms for SLH-DSA"}

This document introduces the registration of the following algorithms in {{-IANA.cose}}:

| Name       | alg | Description |
|-------------|------|-------------|
| SLH-DSA-SHA2-128s  | TBD1 (-51) | CBOR Object Signing Algorithm for SLH-DSA-SHA2-128s |
| SLH-DSA-SHAKE-128s | TBD2 (-52) | CBOR Object Signing Algorithm for SLH-DSA-SHAKE-128s |
{: #cose-algorithms align="left" title="COSE Algorithms for SLH-DSA"}

{{FIPS-205}} defines twelve parameter sets in total, across three NIST
security categories (1, 3, 5), two hash function families (SHA2 and SHAKE),
and two size/speed tradeoffs (small `s` and fast `f`). This document
registers only the two NIST Category 1, "small" parameter sets - one for
each hash function family. Limiting the initial registration to a small,
symmetric set is intended to maximize interoperability among early
implementations and to keep the JOSE and COSE registries focused.

SLH-DSA is expected to be most relevant for deployments that specifically
need a stateless hash-based digital signature scheme, or that want algorithmic
diversity as a fallback to other post-quantum signature schemes. Firmware
signing in embedded systems is often cited as a primary use case for this
algorithm. Registration of these algorithms does not imply that every
general-purpose JOSE or COSE implementation is expected to support them.

The algorithms registered in this document identify pure SLH-DSA, as
specified by `slh_sign` in Section 10.2.1 of {{FIPS-205}} and `slh_verify`
in Section 10.3 of {{FIPS-205}}, instantiated with the parameter set of the
same name from Table 2 of {{FIPS-205}}. The algorithms registered in this
document MUST NOT be used with `hash_slh_sign` or `hash_slh_verify`.

Future documents may register additional SLH-DSA parameter sets — including
higher security categories or the "fast" variants — as deployment
experience identifies the need.

# SLH-DSA Keys

Private and public keys are produced to enable the sign and verify operations for each of the SLH-DSA algorithms.

The SLH-DSA Algorithm Family uses the Algorithm Key Pair (AKP) key type, as defined in {{-ML-DSA}}. Reusing AKP gives SLH-DSA keys the same JOSE and COSE parameter names, serialization rules, and thumbprint processing used by other algorithms that use AKP.

The specific algorithms for SLH-DSA, namely SLH-DSA-SHA2-128s and SLH-DSA-SHAKE-128s, are defined in this document and are used in the `alg` value of an AKP key representation to specify the corresponding algorithm.

{{FIPS-205}} represents an SLH-DSA public key as `PK = (PK.seed, PK.root)`,
where each component is `n` bytes. An SLH-DSA private key is represented as
`SK = (SK.seed, SK.prf, PK.seed, PK.root)`, where each component is `n`
bytes. The value of `n` for each parameter set is defined in Table 2 of
{{FIPS-205}}.

For SLH-DSA AKP keys, the `pub` parameter MUST contain the SLH-DSA public
key `PK.seed || PK.root`. The `priv` parameter, when present, MUST contain
the SLH-DSA private key `SK.seed || SK.prf || PK.seed || PK.root` and MUST
NOT be present in public keys.

For the two algorithms registered in this document, `n` is 16 bytes.
Therefore, `pub` MUST be 32 bytes and `priv`, when present, MUST be 64
bytes.

The compact size of SLH-DSA public keys can be useful when JWKs are used to
convey verification keys, including by protocols that use JWKs independently
of JWS signatures.

Thumbprints for SLH-DSA keys are computed according to the process described in {{-ML-DSA}}.

# Signing and Verification

Signatures are produced and verified using the procedures defined in {{FIPS-205}}.
The SLH-DSA signing function takes a context string `ctx` as input.
For the algorithms registered in this document, the `ctx` parameter MUST be the empty string.
Implementations that produce or accept a non-empty `ctx` value will not interoperate.

Here the empty string is the zero-length byte string, that is, a `ctx` value
whose length is zero. Some cryptographic interfaces represent an absent context
as a nil or NULL value rather than as a zero-length byte string; where such a
representation exists, it is equivalent to the empty context string for the
algorithms registered in this document. Implementations MUST NOT substitute a
placeholder value for the empty context string. In particular, a single zero
byte is a context string of length one, not the empty context string. As
described in Sections 10.2.1 and 10.3 of {{FIPS-205}}, pure SLH-DSA signing and
verification construct the message input by prepending a one-byte domain
separator, a one-byte encoding of the length of `ctx`, and `ctx` itself to the
content to be signed. For the algorithms registered in this document that prefix
is therefore two zero bytes, and a signature produced over any other prefix will
not verify.

Signatures are encoded as the byte strings produced by the signature generation algorithms in {{FIPS-205}}.
When producing JSON Web Signatures, the signature byte strings are base64url encoded, as defined in {{Section 2 of RFC7515}}.
When producing COSE signatures, no encoding is needed; see {{Section 4 of RFC9052}} for more details on how COSE signatures are created.
For the algorithms registered in this document, the signature byte string is
7856 bytes, as specified in Table 2 of {{FIPS-205}}. The corresponding
base64url-encoded JWS signature value is 10475 characters.

# Security Considerations

The security considerations of {{-JWS}}, {{-JWK}} and {{-COSE-Alg}} apply to this specification as well.

A detailed security analysis of SLH-DSA is beyond the scope of this specification; see {{FIPS-205}} for additional details.

The following considerations apply to all parameter sets described in this specification.

## Pre-Hash and Hashing Considerations

{{FIPS-205}} defines two variants of the signature scheme: SLH-DSA, which
takes the message directly as input, and HashSLH-DSA, which applies an
external pre-hash to the message before invocation.
This document specifies only SLH-DSA for use with JOSE and COSE.
HashSLH-DSA is out of scope.

A key identified by an SLH-DSA algorithm identifier defined in this document
MUST NOT be used to generate or verify a HashSLH-DSA signature, and vice
versa. The same constraint is described for X.509 deployments in
{{RFC9909}}.

This document does not define or register separate `HashSLH-DSA` algorithm
identifiers for JOSE or COSE. Doing so would require distinct algorithm
registrations and would introduce additional implementation and
interoperability complexity.

For many JOSE and COSE use cases, this restriction is acceptable because the
application can already structure the signed content in a way that limits
the amount of data processed directly by the signature algorithm. In
particular, COSE applications that need to sign large payloads, detached
content, or remotely held content may use the COSE Hash Envelope mechanism
{{I-D.ietf-cose-hash-envelope}}. JOSE applications with similar operational
requirements can use a detached JWS payload, or can define an
application-specific signed payload that carries the digest value, the
digest algorithm, and the rules for recomputing and comparing the digest.

Hash Envelope can provide operational properties similar to those sought
from a pre-hash signature mode, such as reduced data transfer to a signer,
reduced buffering requirements, and simplified remote-signing workflows.
However, Hash Envelope is not cryptographically equivalent to HashSLH-DSA.
HashSLH-DSA binds the identity of the pre-hash function into the signature
through a domain separator inside the signing algorithm; Hash Envelope
carries the digest and the digest algorithm at the COSE layer, outside the
signature's domain separator.

Applications that use Hash Envelope, or an application-specific JOSE digest
payload, together with SLH-DSA need to ensure that the digest is recomputed
over the original content and compared with the signed digest before
treating the signature as valid for that content. Profiles that rely on
this construction SHOULD specify the permitted hash algorithms and the
verification procedure explicitly.

If future deployment experience shows clear demand for algorithm-level
pre-hash semantics in JOSE or COSE, separate registrations for HashSLH-DSA
could be defined in a future specification.

## Validating Public Keys

Before using an SLH-DSA AKP key, implementations MUST validate all
algorithm-related key parameters. For the algorithms registered in this
document, the `alg` parameter MUST identify one of the SLH-DSA algorithms
registered in this document and the `pub` parameter MUST be present and MUST
have the length specified in {{slh-dsa-keys}}.

These checks correspond to the public-key validation requirement in Section
3.1 of {{FIPS-205}}, which requires implementations to verify that the
public key is `2n` bytes in length. If assurance of private-key possession
is obtained via regeneration, the private key checks in Section 3.1 of
{{FIPS-205}} also apply: the private key is checked to be `4n` bytes in
length, `PK.root` is recomputed from `SK.seed` and `PK.seed`, and the
recomputed value is compared with the value in the private key.

## Side-Channel Attacks

Implementations of the signing algorithm SHOULD protect the secret key from side-channel attacks. Any implementation of SLH-DSA signing algorithms SHOULD employ at least the following best practices:

- Constant-time operation
- Consistent instruction sequence and memory access
- Uniform sampling without information leakage

## Deterministic and Randomized Signing

{{FIPS-205}} permits both deterministic and randomized (hedged) signing.
The choice of mode is implementation-defined; signatures produced under
either mode are verifiable with the same public key, and verifiers cannot
and need not distinguish them.

Deterministic signing is simpler and removes a runtime dependency on a
random number generator at signing time. Randomized signing offers
improved resistance to fault and side-channel attacks that target the
signing operation, at the cost of requiring a high-quality random source
on every invocation.

Implementations that select randomized signing MUST source the per-signature
randomness from a trusted and cryptographically secure source as described
in Section 9.2 of {{FIPS-205}}.

## Randomness Considerations

All random values used by SLH-DSA key generation or randomized signing MUST
originate from a trusted and cryptographically secure source of randomness.

# IANA Considerations

## New COSE Algorithms

IANA is requested to add the following entries to the COSE Algorithms Registry.

The following registration templates are provided in accordance with the procedures described in {{-COSE-Alg}} and {{-COSE-Header-Parameters}}.

### SLH-DSA-SHA2-128s

* Name: SLH-DSA-SHA2-128s
* Value: TBD1 (requested assignment -51)
* Description: CBOR Object Signing Algorithm for SLH-DSA-SHA2-128s
* Capabilities: `[kty]`
* Change Controller: IETF
* Reference: RFC XXXX
* Recommended: Yes

### SLH-DSA-SHAKE-128s

* Name: SLH-DSA-SHAKE-128s
* Value: TBD2 (requested assignment -52)
* Description: CBOR Object Signing Algorithm for SLH-DSA-SHAKE-128s
* Capabilities: `[kty]`
* Change Controller: IETF
* Reference: RFC XXXX
* Recommended: Yes

## New JOSE Algorithms

IANA is requested to add the following entries to the JSON Web Signature and Encryption Algorithms Registry.

The following completed registration templates are provided as described in {{-JWA}}.

### SLH-DSA-SHA2-128s

* Algorithm Name: SLH-DSA-SHA2-128s
* Algorithm Description: SLH-DSA-SHA2-128s as described in FIPS 205.
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{FIPS-205}}

### SLH-DSA-SHAKE-128s

* Algorithm Name: SLH-DSA-SHAKE-128s
* Algorithm Description: SLH-DSA-SHAKE-128s as described in FIPS 205.
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{FIPS-205}}

--- back

# Relationship to SLH-DSA in CMS

{{RFC9814}} specifies conventions for using SLH-DSA with the Cryptographic
Message Syntax (CMS). This document follows the same FIPS 205 definition of
SLH-DSA key material and signatures, but applies it to JOSE and COSE.

Both specifications use the FIPS 205 public key value `PK.seed || PK.root`
and private key value `SK.seed || SK.prf || PK.seed || PK.root`. In
{{RFC9814}}, these values appear as the SLH-DSA public and private key
contents associated with ASN.1 public-key and private-key containers. In this
document, the same values are carried in AKP `pub` and `priv` key parameters.

The main differences are protocol and registry choices:

* {{RFC9814}} assigns object identifiers for all twelve FIPS 205 SLH-DSA
  parameter sets. This document registers only `SLH-DSA-SHA2-128s` and
  `SLH-DSA-SHAKE-128s` for JOSE and COSE.

* {{RFC9814}} identifies SLH-DSA algorithms with ASN.1 AlgorithmIdentifier
  object identifiers whose parameters are absent. This document identifies
  them with JOSE algorithm names and COSE algorithm values, and with the
  `alg` parameter in AKP keys.

* {{RFC9814}} defines CMS `SignedData` conventions, including how SLH-DSA is
  used when CMS signed attributes are present. This document does not define
  an equivalent signed-attributes construction. Applications that need to
  avoid signing large content directly can use JOSE or COSE mechanisms such
  as detached JWS payloads, COSE Hash Envelope, or application-specific
  signed digest payloads as discussed in {{pre-hash-and-hashing-considerations}}.

* Both specifications use pure SLH-DSA with an empty context string for the
  algorithms they define, and neither defines HashSLH-DSA algorithm
  identifiers for its target protocol.

# Examples

These examples were generated using Cloudflare CIRCL and
cross-validated against the Trail of Bits go-slh-dsa implementation.
The source code used to generate these examples is available in the
`examples/` directory of the
[cose-wg/draft-ietf-cose-sphincs-plus](https://github.com/cose-wg/draft-ietf-cose-sphincs-plus)
repository.

## JOSE

### SLH-DSA-SHA2-128s

~~~json
{::include-fold testvectors/SLH-DSA-SHA2-128s/private-jwk.json}
~~~
{: #SLH-DSA-SHA2-128s-private-jwk title="Example SLH-DSA-SHA2-128s Private JSON Web Key"}

~~~json
{::include-fold testvectors/SLH-DSA-SHA2-128s/public-jwk.json}
~~~
{: #SLH-DSA-SHA2-128s-public-jwk title="Example SLH-DSA-SHA2-128s Public JSON Web Key"}

### SLH-DSA-SHAKE-128s

~~~json
{::include-fold testvectors/SLH-DSA-SHAKE-128s/private-jwk.json}
~~~
{: #SLH-DSA-SHAKE-128s-private-jwk title="Example SLH-DSA-SHAKE-128s Private JSON Web Key"}

~~~json
{::include-fold testvectors/SLH-DSA-SHAKE-128s/public-jwk.json}
~~~
{: #SLH-DSA-SHAKE-128s-public-jwk title="Example SLH-DSA-SHAKE-128s Public JSON Web Key"}

## COSE

### SLH-DSA-SHA2-128s

~~~~ cbor-diag
{::include-fold testvectors/SLH-DSA-SHA2-128s/cose-key.diag}
~~~~
{: #SLH-DSA-SHA2-128s-private-cose-key title="Example SLH-DSA-SHA2-128s COSE Key"}

~~~~ cbor-diag
{::include testvectors/SLH-DSA-SHA2-128s/cose-sign1.diag}
~~~~
{: #SLH-DSA-SHA2-128s-cose-sign1 title="Example SLH-DSA-SHA2-128s COSE Sign1"}

### SLH-DSA-SHAKE-128s

~~~~ cbor-diag
{::include-fold testvectors/SLH-DSA-SHAKE-128s/cose-key.diag}
~~~~
{: #SLH-DSA-SHAKE-128s-private-cose-key title="Example SLH-DSA-SHAKE-128s COSE Key"}

~~~~ cbor-diag
{::include testvectors/SLH-DSA-SHAKE-128s/cose-sign1.diag}
~~~~
{: #SLH-DSA-SHAKE-128s-cose-sign1 title="Example SLH-DSA-SHAKE-128s COSE Sign1"}

# Acknowledgments
{:numbered="false"}

We would like to thank Roy Williams, Cedric Fournet, Simo Sorce, Ilari Liusvaara, Neil Madden, Anders Rundgren, David Waite, Russ Housley, Brian Sipos, Lucas Prabel, Filip Skokan, and Kris Kwiatkowski for their review feedback.
