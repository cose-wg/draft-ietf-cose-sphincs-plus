---
title: "SLH-DSA for JOSE and COSE"
abbrev: "jose-cose-sphincs-plus"
category: std

docname: draft-ietf-cose-sphincs-plus-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
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

informative:
  FIPS-205:
    title: "Stateless Hash-Based Digital Signature Standard"
    target: https://csrc.nist.gov/pubs/fips/205/ipd
  NIST-PQC-2022:
    title: "Selected Algorithms 2022"
    target: https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022


--- abstract

This document describes JOSE and COSE serializations for SLH-DSA, which was derived from SPHINCS+, a Post-Quantum Cryptography (PQC) based digital signature scheme.

This document does not define any new cryptography, only seralizations of existing cryptographic systems described in {{FIPS-205}}.

Note to RFC Editor: This document should not proceed to AUTH48 until NIST completes paramater tuning and selection as a part of the [PQC](https://csrc.nist.gov/projects/post-quantum-cryptography) standardization process.


--- middle

# Introduction

SLH-DSA is derived from Version 3.1 of SPHINCS+, as noted in {{FIPS-205}}.

SPHINCS+ is one of the post quantum cryptography algorithms selected in {{NIST-PQC-2022}}.

TODO: Add complete examples for `SLH-DSA-SHA2-128s`, `SLH-DSA-SHAKE-128s`, `SLH-DSA-SHA2-128f`... ( all of them? really?)


# Terminology

{::boilerplate bcp14-tagged}

# The SLH-DSA Algorithm Family

The SLH-DSA Signature Scheme is paramaterized to support different security level.

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

# The SLH-DSA Key Type

Private and Public Keys are produced to enable the sign and verify opertaions for each of the SLH-DSA Algorithms.

This document requests the registration of the following key types in {{-IANA.jose}}:

| Name    | kty | Description
|---
| SLH-DSA  | SLH-DSA     | JSON Web Key Type for the SLH-DSA Algorithm Family.
{: #jose-key-type align="left" title="JSON Web Key Type for SLH-DSA"}

This document requests the registration of the following algorithms in {{-IANA.cose}}:

| Name       | kty | Description
|---
| SLH-DSA  | TBD (requested assignment 8)     | COSE Key Type for the SLH-DSA Algorithm Family.
{: #cose-key-type align="left" title="COSE Key Type for SLH-DSA"}


# Security Considerations

TODO Security

# IANA Considerations

## Additions to Existing Registries

### New COSE Algorithms

#### SLH-DSA-SHA2-128s

* Name: SLH-DSA-SHA2-128s
* Label: TBD (requested assignment -51)
* Value type: int
* Value registry: {{-IANA.cose}}
* Description: CBOR Object Signing Algorithm for SLH-DSA-SHA2-128s

#### SLH-DSA-SHAKE-128s

* Name: SLH-DSA-SHAKE-128s
* Label: TBD (requested assignment -52)
* Value type: int
* Value registry: {{-IANA.cose}}
* Description: CBOR Object Signing Algorithm for SLH-DSA-SHAKE-128s

#### SLH-DSA-SHA2-128f

* Name: SLH-DSA-SHA2-128f
* Label: TBD (requested assignment -53)
* Value type: int
* Value registry: {{-IANA.cose}}
* Description: CBOR Object Signing Algorithm for SLH-DSA-SHA2-128f

### New COSE Key Types

#### SLH-DSA

* Name: SLH-DSA
* Label: TBD (requested assignment 8)
* Value type: int
* Value registry: {{-IANA.cose}}
* Description: COSE Key Type for the SLH-DSA Algorithm Family

### New JOSE Algorithms

#### SLH-DSA-SHA2-128s

* Name: SLH-DSA-SHA2-128s
* Value registry: {{-IANA.jose}} Algorithms
* Description: JSON Web Signature Algorithm for SLH-DSA-SHA2-128s

#### SLH-DSA-SHAKE-128s

* Name: SLH-DSA-SHAKE-128s
* Value registry: {{-IANA.jose}} Algorithms
* Description: JSON Web Signature Algorithm for SLH-DSA-SHAKE-128s

#### SLH-DSA-SHA2-128f

* Name: SLH-DSA-SHA2-128f
* Value registry: {{-IANA.jose}} Algorithms
* Description: JSON Web Signature Algorithm for SLH-DSA-SHA2-128f

### New JOSE Key Types

#### SLH-DSA

* Name: SLH-DSA
* Value registry: {{-IANA.jose}} Algorithms
* Description: JSON Web Key Type for the SLH-DSA Algorithm Family.


--- back


# Examples

## JOSE

### Key Pair

~~~json
{
  "kty": "SLH-DSA",
  "alg": "SLH-DSA-SHA2-128s",
  "pub": "V53SIdVF...uvw2nuCQ",
  "priv": "V53SIdVF...cDKLbsBY"
}
~~~
{: #SLH-DSA-SHA2-128s-private-jwk title="Example SLH-DSA-SHA2-128s Private JSON Web Key"}

~~~json
{
  "kty": "SLH-DSA",
  "alg": "SLH-DSA-SHA2-128s",
  "pub": "V53SIdVF...uvw2nuCQ"
}
~~~
{: #SLH-DSA-SHA2-128s-public-jwk title="Example SLH-DSA-SHA2-128s Public JSON Web Key"}

### Thumbprint URI

TODO

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
  1: 8,                             / SLH-DSA Key Type            /
  3: -51,                           / SLH-DSA-SHA2-128s Algorithm /
  -13: h'7803c0f9...3f6e2c70',      / SLH-DSA Private Key         /
  -14: h'7803c0f9...3bba7abd',      / SLH-DSA Public Key          /
}
~~~~
{: #SLH-DSA-SHA2-128s-private-cose-key title="Example SLH-DSA-SHA2-128s Private COSE Key"}

~~~~ cbor-diag
{                                   / COSE Key                    /
  1: 8,                             / SLH-DSA Key Type            /
  3: -51,                           / SLH-DSA-SHA2-128s Algorithm /
  -13: h'7803c0f9...3f6e2c70'       / SLH-DSA Private Key         /
}
~~~~
{: #SLH-DSA-SHA2-128s-public-cose-key title="Example SLH-DSA-SHA2-128s Public COSE Key"}

### Thumbprint URI

TODO

### COSE Sign 1


~~~~ cbor-diag
{        / Protected                   /
  1: -51 / SLH-DSA-SHA2-128s Algorithm /
}
~~~~
{: #SLH-DSA-SHA2-128s-cose-protected-header-diagnostic title="Example SLH-DSA-SHA2-128s COSE Protected Header"}


~~~~ cbor-diag
18(                                 / COSE Sign 1            /
    [
      h'a10139d902',                / Protected              /
      {},                           / Unprotected            /
      h'66616b65',                  / Payload                /
      h'53e855e8...0f263549'        / Signature              /
    ]
)
~~~~
{: #SLH-DSA-SHA2-128s-cose-sign-1-diagnostic title="Example SLH-DSA-SHA2-128s COSE Sign 1"}


# Acknowledgments
{:numbered="false"}

TODO acknowledge.
