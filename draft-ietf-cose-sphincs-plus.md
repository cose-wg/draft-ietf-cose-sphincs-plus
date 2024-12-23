---
title: "SLH-DSA for JOSE and COSE"
abbrev: "jose-cose-sphincs-plus"
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
    organization: Transmute
    email: "orie@transmute.industries"
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
  IANA.jose: IANA.jose
  IANA.cose: IANA.cose
  RFC7515: JWS
  RFC7517: JWK
  RFC9053: COSE
  I-D.draft-ietf-cose-dilithium: ML-DSA

informative:
  FIPS-205:
    title: "Stateless Hash-Based Digital Signature Standard"
    target: https://doi.org/10.6028/NIST.FIPS.205
  NIST-PQC-2022:
    title: "Selected Algorithms 2022"
    target: https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022


--- abstract

This document describes JOSE and COSE serializations for SLH-DSA, which was derived from SPHINCS+, a Post-Quantum Cryptography (PQC) based digital signature scheme.
This document does not define any new cryptography, only serializations of existing cryptographic systems described in {{FIPS-205}}.

--- middle

# Introduction

This document describes JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE) serializations for the Stateless Hash-Based Digital Signature Standard (SLH-DSA), which was derived from Version 3.1 of SPHINCS+, a Post-Quantum Cryptography (PQC) based digital signature scheme.

This document does not define any new cryptography, only serializations of existing cryptographic systems described in {{FIPS-205}}.

This document builds on the Algorithm Key Pair (AKP) type as defined in {{-ML-DSA}}. The AKP type enables flexible representation of keys used across different post-quantum cryptographic algorithms, including SLH-DSA.

# Terminology

{::boilerplate bcp14-tagged}

# The SLH-DSA Algorithm Family

The SLH-DSA Signature Scheme is parameterized to support different security levels.

This document requests the registration of the following algorithms in {{-IANA.jose}}:

| Name       | alg | Description
|---
| SLH-DSA-SHA2-128s  | SLH-DSA-SHA2-128s     | JSON Web Signature Algorithm for SLH-DSA-SHA2-128s
| SLH-DSA-SHAKE-128s  | SLH-DSA-SHAKE-128s     | JSON Web Signature Algorithm for SLH-DSA-SHAKE-128s
| SLH-DSA-SHA2-128f  | SLH-DSA-SHA2-128f     | JSON Web Signature Algorithm for SLH-DSA-SHA2-128f
{: #jose-algorithms align="left" title="JOSE algorithms for SLH-DSA"}

This document requests the registration of the following algorithms in {{-IANA.cose}}:

| Name       | alg | Description
|---
| SLH-DSA-SHA2-128s  | TBD (requested assignment -51)     | CBOR Object Signing Algorithm for SLH-DSA-SHA2-128s
| SLH-DSA-SHAKE-128s  | TBD (requested assignment -52)     | CBOR Object Signing Algorithm for SLH-DSA-SHAKE-128s
| SLH-DSA-SHA2-128f  | TBD (requested assignment -53)     | CBOR Object Signing Algorithm for SLH-DSA-SHA2-128f
{: #cose-algorithms align="left" title="COSE algorithms for SLH-DSA"}

# SLH-DSA Keys

Private and Public Keys are produced to enable the sign and verify operations for each of the SLH-DSA Algorithms. The SLH-DSA Algorithm Family uses the Algorithm Key Pair (AKP) key type, as defined in {{-ML-DSA}}. This ensures compatibility across different cryptographic algorithms that use AKP for key representation.

The specific algorithms for SLH-DSA, such as SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-128s, and SLH-DSA-SHA2-128f, are defined in this document and are used in the alg value of an AKP key representation to specify the algorithm that corresponds to the key.
Like ML-DSA keys, SLH-DSA keys use the AKP Key Type.

The thumbprints for SLH-DSA keys are also computed according to the process described in {{-ML-DSA}}

# Security Considerations

The security considerations of {{-JWS}}, {{-JWK}} and {{-COSE}} applies to this specification as well.

A detailed security analysis of SLH-DSA is beyond the scope of this specification, see {{FIPS-205}} for additional details.

The following considerations apply to all parameter sets described in this specification.

## Validating public keys

All algorithms in that operate on public keys require first validating
those keys. For the sign, verify and proof schemes, the use of
KeyValidate is REQUIRED.

## Side channel attacks

Implementations of the signing algorithm SHOULD protect the secret key
from side-channel attacks. Multiple best practices exist to protect
against side-channel attacks. Any implementation of the SLH-DSA
signing algorithms SHOULD utilize the following best practices at a
minimum:

- Constant timing - the implementation should ensure that constant time
  is utilized in operations
- Sequence and memory access persistance - the implementation SHOULD
  execute the exact same sequence of instructions (at a machine level)
  with the exact same memory access independent of which polynomial is
  being operated on.
- Uniform sampling - care should be given in implementations to preserve
  the property of uniform sampling in implementation and to prevent
  information leakage.

## Randomness considerations

It is recommended that the all nonces are from a trusted source of
randomness.

# IANA Considerations

## Additions to Existing Registries

### New COSE Algorithms

IANA is requested to add the following entries to the COSE Algorithms Registry.
The following completed registration templates are provided as described in RFC9053 and RFC9054.

#### SLH-DSA-SHA2-128s

* Name: SLH-DSA-SHA2-128s
* Value: TBD (requested assignment -51)
* Description: CBOR Object Signing Algorithm for SLH-DSA-SHA2-128s
* Capabilities: `[kty]`
* Reference: RFC XXXX
* Recommended: Yes

#### SLH-DSA-SHAKE-128s

* Name: SLH-DSA-SHAKE-128s
* Value: TBD (requested assignment -52)
* Description: CBOR Object Signing Algorithm for SLH-DSA-SHAKE-128s
* Capabilities: `[kty]`
* Reference: RFC XXXX
* Recommended: Yes

#### SLH-DSA-SHA2-128f

* Name: SLH-DSA-SHA2-128f
* Value: TBD (requested assignment -53)
* Description: CBOR Object Signing Algorithm for SLH-DSA-SHA2-128f
* Capabilities: `[kty]`
* Reference: RFC XXXX
* Recommended: Yes

### New JOSE Algorithms

IANA is requested to add the following entries to the JSON Web Signature and Encryption Algorithms Registry.
The following completed registration templates are provided as described in RFC7518.

#### SLH-DSA-SHA2-128s

* Algorithm Name: SLH-DSA-SHA2-128s
* Algorithm Description: SLH-DSA-SHA2-128s as described in FIPS 205.
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Value registry: {{-IANA.jose}} Algorithms
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{FIPS-205}}

#### SLH-DSA-SHAKE-128s

* Algorithm Name: SLH-DSA-SHAKE-128s
* Algorithm Description: SLH-DSA-SHAKE-128s as described in FIPS 205.
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Value registry: {{-IANA.jose}} Algorithms
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{FIPS-205}}

#### SLH-DSA-SHA2-128f

* Algorithm Name: SLH-DSA-SHA2-128f
* Algorithm Description: SLH-DSA-SHA2-128f as described in FIPS 205.
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Value registry: {{-IANA.jose}} Algorithms
* Specification Document(s): RFC XXXX
* Algorithm Analysis Documents(s): {{FIPS-205}}

--- back

# Examples

## JOSE

### Key Pair

~~~json
{
  "kty": "AKP",
  "alg": "SLH-DSA-SHA2-128s",
  "pub": "V53SIdVF...uvw2nuCQ",
  "priv": "V53SIdVF...cDKLbsBY"
}
~~~
{: #SLH-DSA-SHA2-128s-private-jwk title="Example SLH-DSA-SHA2-128s Private JSON Web Key"}

~~~json
{
  "kty": "AKP",
  "alg": "SLH-DSA-SHA2-128s",
  "pub": "V53SIdVF...uvw2nuCQ"
}
~~~
{: #SLH-DSA-SHA2-128s-public-jwk title="Example SLH-DSA-SHA2-128s Public JSON Web Key"}

### Thumbprint

The thumbprint is computed as described in

### JSON Web Signature


~~~json
{
  "alg": "SLH-DSA-SHA2-128s"
}
~~~
{: #SLH-DSA-SHA2-128s-jose-protected-header title="Example SLH-DSA-SHA2-128s Decoded Protected Header"}

~~~
eyJhbGciOiJ...LCJraWQiOiI0MiJ9\
.\
eyJpc3MiOiJ1cm46d...XVpZDo0NTYifQ\
.\
5MSEgQ0dZB4SeLC...AAAAAABIhMUE
~~~
{: #SLH-DSA-SHA2-128s-jose-jws title="Example SLH-DSA-SHA2-128s Compact JSON Web Signature"}

## COSE

### Key Pair

~~~~ cbor-diag
{                                   / COSE Key                    /
  1: 7,                             / AKP Key Type                /
  3: -51,                           / SLH-DSA-SHA2-128s Algorithm /
  -1: h'7803c0f9...3f6e2c70',       / AKP Private Key             /
  -2: h'7803c0f9...3bba7abd',       / AKP Public Key              /
}
~~~
{: #SLH-DSA-SHA2-128s-private-cose-key title="Example SLH-DSA-SHA2-128s Private COSE Key"}

~~~~ cbor-diag
{                                   / COSE Key                    /
  1: 7,                             / AKP Key Type                /
  3: -51,                           / SLH-DSA-SHA2-128s Algorithm /
  -2: h'7803c0f9...3bba7abd',       / AKP Public Key              /
}
~~~~
{: #SLH-DSA-SHA2-128s-public-cose-key title="Example SLH-DSA-SHA2-128s Public COSE Key"}

### Thumbprint URI

TODO

### COSE Sign 1

~~~~ cbor-diag
/ cose-sign1 / 18(
  [
    / protected / <<{
      / algorithm / 1 : -51 / SLH-DSA-SHA2-128s /
    }>>
    / unprotected / {},
    / payload / h'66616b65',
    / signature / h'53e855e8...0f263549'
  ]
)
~~~~
{: #SLH-DSA-SHA2-128s-cose-sign-1-diagnostic title="Example SLH-DSA-SHA2-128s COSE Sign 1"}


# Acknowledgments
{:numbered="false"}

We would like to thank Roy Williams, Cedric Fournet, Simo Sorce, Ilari Liusvaara, Neil Madden, Anders Rundgren, David Waite, and Russ Housley for their review feedback.
