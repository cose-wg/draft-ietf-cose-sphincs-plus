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
    region: Bavaria
    country: Germany
    code: 85577
    email: hannes.tschofenig@gmx.net

contributor:
 -
    fullname: "Rafael Misoczki"
    organization: Google
    email: "rafaelmisoczki@google.com"
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
  I-D.ietf-cose-dilithium: ML-DSA
  FIPS-205:
    title: "Stateless Hash-Based Digital Signature Standard"
    target: https://doi.org/10.6028/NIST.FIPS.205

informative:
  IANA.jose: IANA.jose
  IANA.cose: IANA.cose
  I-D.ietf-cose-hash-envelope:
  RFC9909:

---

--- abstract

This document specifies JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE) serializations for Stateless Hash-Based Digital Signature Standard (SLH-DSA), a Post-Quantum Cryptography (PQC) digital signature scheme defined in US NIST FIPS 205.


--- middle

# Introduction

This document specifies JSON Object Signing and Encryption (JOSE) {{-JWS}} and CBOR Object Signing and Encryption (COSE) {{-COSE}} serializations for the Stateless Hash-Based Digital Signature Standard (SLH-DSA), which was derived from Version 3.1 of SPHINCS+, a Post-Quantum Cryptography (PQC) based digital signature scheme standardized in {{FIPS-205}}.

This document builds on the Algorithm Key Pair (AKP) type, as defined in {{-ML-DSA}}. The AKP type enables flexible representation of keys used across different post-quantum cryptographic algorithms, including SLH-DSA.

# Terminology

{::boilerplate bcp14-tagged}

# The SLH-DSA Algorithm Family

The SLH-DSA Signature Scheme is parameterized to support different security levels.

This document introduces the registration of the following algorithms in {{-IANA.jose}}:

| Name       | alg | Description |
|-------------|------|-------------|
| SLH-DSA-SHA2-128s  | SLH-DSA-SHA2-128s     | JSON Web Signature Algorithm for SLH-DSA-SHA2-128s |
| SLH-DSA-SHAKE-128s | SLH-DSA-SHAKE-128s    | JSON Web Signature Algorithm for SLH-DSA-SHAKE-128s |
| SLH-DSA-SHA2-128f  | SLH-DSA-SHA2-128f     | JSON Web Signature Algorithm for SLH-DSA-SHA2-128f |
{: #jose-algorithms align="left" title="JOSE Algorithms for SLH-DSA"}

This document introduces the registration of the following algorithms in {{-IANA.cose}}:

| Name       | alg | Description |
|-------------|------|-------------|
| SLH-DSA-SHA2-128s  | TBD1 (-51) | CBOR Object Signing Algorithm for SLH-DSA-SHA2-128s |
| SLH-DSA-SHAKE-128s | TBD2 (-52) | CBOR Object Signing Algorithm for SLH-DSA-SHAKE-128s |
| SLH-DSA-SHA2-128f  | TBD3 (-53) | CBOR Object Signing Algorithm for SLH-DSA-SHA2-128f |
{: #cose-algorithms align="left" title="COSE Algorithms for SLH-DSA"}

# SLH-DSA Keys

Private and public keys are produced to enable the sign and verify operations for each of the SLH-DSA algorithms.

The SLH-DSA Algorithm Family uses the Algorithm Key Pair (AKP) key type, as defined in {{-ML-DSA}}. This ensures compatibility across different cryptographic algorithms that use AKP for key representation.

The specific algorithms for SLH-DSA, such as SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-128s, and SLH-DSA-SHA2-128f, are defined in this document and are used in the `alg` value of an AKP key representation to specify the corresponding algorithm.

Thumbprints for SLH-DSA keys are computed according to the process described in {{-ML-DSA}}.

# Signing and Verification

Signatures are produced and verified using the procedures defined in {{FIPS-205}}.
The SLH-DSA signing function takes a context string `ctx` as input.
For the algorithms registered in this document, the `ctx` parameter MUST be the empty string.
Implementations that produce or accept a non-empty `ctx` value will not interoperate.

Signatures are encoded as the byte strings produced by the signature generation algorithms in {{FIPS-205}}.
When producing JSON Web Signatures, the signature byte strings are base64url encoded.
When producing COSE signatures, no encoding is needed; see {{Section 4 of RFC9052}} for more details on how COSE signatures are created.

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
particular, applications that need to sign large payloads, detached
content, or remotely held content may use the COSE Hash Envelope mechanism
{{I-D.ietf-cose-hash-envelope}}.

Hash Envelope can provide operational properties similar to those sought
from a pre-hash signature mode, such as reduced data transfer to a signer,
reduced buffering requirements, and simplified remote-signing workflows.
However, Hash Envelope is not cryptographically equivalent to HashSLH-DSA.
HashSLH-DSA binds the identity of the pre-hash function into the signature
through a domain separator inside the signing algorithm; Hash Envelope
carries the digest and the digest algorithm at the COSE layer, outside the
signature's domain separator.

Applications that use Hash Envelope together with SLH-DSA need to ensure
that the digest is recomputed over the original content and compared with
the signed digest before treating the signature as valid for that content.
Profiles that rely on this construction SHOULD specify the permitted hash
algorithms and the verification procedure explicitly.

If future deployment experience shows clear demand for algorithm-level
pre-hash semantics in JOSE or COSE, separate registrations for HashSLH-DSA
could be defined in a future specification.

## Validating Public Keys

All algorithms that operate on public keys require validation before use. For sign, verify and proof schemes, the use of `KeyValidate` is REQUIRED.

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

## Randomness considerations

All nonces MUST originate from a trusted and cryptographically secure source of randomness.

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

### SLH-DSA-SHA2-128f

* Name: SLH-DSA-SHA2-128f
* Value: TBD3 (requested assignment -53)
* Description: CBOR Object Signing Algorithm for SLH-DSA-SHA2-128f
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

### SLH-DSA-SHA2-128f

* Algorithm Name: SLH-DSA-SHA2-128f
* Algorithm Description: SLH-DSA-SHA2-128f as described in FIPS 205.
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{FIPS-205}}

--- back

# Examples

These examples were generated using Cloudflare CIRCL and
cross-validated against the Trail of Bits go-slh-dsa implementation.
Source code is available in the `examples/` directory.

## JOSE

### SLH-DSA-SHA2-128s

~~~json
{::include testvectors/SLH-DSA-SHA2-128s/private-jwk.json}
~~~
{: #SLH-DSA-SHA2-128s-private-jwk title="Example SLH-DSA-SHA2-128s Private JSON Web Key"}

~~~json
{::include testvectors/SLH-DSA-SHA2-128s/public-jwk.json}
~~~
{: #SLH-DSA-SHA2-128s-public-jwk title="Example SLH-DSA-SHA2-128s Public JSON Web Key"}

### SLH-DSA-SHAKE-128s

~~~json
{::include testvectors/SLH-DSA-SHAKE-128s/private-jwk.json}
~~~
{: #SLH-DSA-SHAKE-128s-private-jwk title="Example SLH-DSA-SHAKE-128s Private JSON Web Key"}

~~~json
{::include testvectors/SLH-DSA-SHAKE-128s/public-jwk.json}
~~~
{: #SLH-DSA-SHAKE-128s-public-jwk title="Example SLH-DSA-SHAKE-128s Public JSON Web Key"}

### SLH-DSA-SHA2-128f

~~~json
{::include testvectors/SLH-DSA-SHA2-128f/private-jwk.json}
~~~
{: #SLH-DSA-SHA2-128f-private-jwk title="Example SLH-DSA-SHA2-128f Private JSON Web Key"}

~~~json
{::include testvectors/SLH-DSA-SHA2-128f/public-jwk.json}
~~~
{: #SLH-DSA-SHA2-128f-public-jwk title="Example SLH-DSA-SHA2-128f Public JSON Web Key"}

## COSE

### SLH-DSA-SHA2-128s

~~~~ cbor-diag
{::include testvectors/SLH-DSA-SHA2-128s/cose-key.diag}
~~~~
{: #SLH-DSA-SHA2-128s-private-cose-key title="Example SLH-DSA-SHA2-128s COSE Key"}

~~~~ cbor-diag
{::include testvectors/SLH-DSA-SHA2-128s/cose-sign1.diag}
~~~~
{: #SLH-DSA-SHA2-128s-cose-sign1 title="Example SLH-DSA-SHA2-128s COSE Sign1"}

### SLH-DSA-SHAKE-128s

~~~~ cbor-diag
{::include testvectors/SLH-DSA-SHAKE-128s/cose-key.diag}
~~~~
{: #SLH-DSA-SHAKE-128s-private-cose-key title="Example SLH-DSA-SHAKE-128s COSE Key"}

~~~~ cbor-diag
{::include testvectors/SLH-DSA-SHAKE-128s/cose-sign1.diag}
~~~~
{: #SLH-DSA-SHAKE-128s-cose-sign1 title="Example SLH-DSA-SHAKE-128s COSE Sign1"}

### SLH-DSA-SHA2-128f

~~~~ cbor-diag
{::include testvectors/SLH-DSA-SHA2-128f/cose-key.diag}
~~~~
{: #SLH-DSA-SHA2-128f-private-cose-key title="Example SLH-DSA-SHA2-128f COSE Key"}

~~~~ cbor-diag
{::include testvectors/SLH-DSA-SHA2-128f/cose-sign1.diag}
~~~~
{: #SLH-DSA-SHA2-128f-cose-sign1 title="Example SLH-DSA-SHA2-128f COSE Sign1"}

# Acknowledgments
{:numbered="false"}

We would like to thank Roy Williams, Cedric Fournet, Simo Sorce, Ilari Liusvaara, Neil Madden, Anders Rundgren, David Waite, and Russ Housley for their review feedback.
