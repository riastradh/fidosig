Fidosig file formats
====================

Every file format handled by fidosig starts with an 8-byte tag,
`FIDOSIGx` where x is a letter indicating the type of file, and ends
with the little-endian 4-byte zlib CRC32 computed over everything
before the CRC.

The file formats are binary, not text, in order to discourage
eyeballing them without formally verifying them.  The CRC is included
in order to detect copy & paste errors for credential sets, and to
discourage hand-editing.

All files are meant to be small enough to fit in memory -- if you are
accepting thousands of signatories on a single document, you probably
don't have much security anyway.  Each credential and signature is
roughly 150 bytes; device attestations may be longer.

Tags
----

- `FIDOSIGC` -- credential set
- `FIDOSIGA` -- device attestation set
- `FIDOSIGS` -- signature set
- `FIDOSIGK` -- private seed for softkey

Additionally, some tags are reserved to derive challenges:

- `FIDOSIGH` -- randomized hash of relying party and message for signatures
- `FIDOSIGU` -- hash of user and relying party for credential creation

Files
-----

### Credential set

```
offset	length	data
0	8	`FIDOSIGC' in US-ASCII (C for `Credentials')
8	*	CBOR map of credential_id to COSE pubkey
*	4	zlib crc32 checksum
```

Credential creation challenge is SHA-256 hash computed over:

```
offset	length	data
0	8	`FIDOSIGU' in US-ASCII (U for `User')
8	*	CBOR map of inputs:
		rp		relying party, map
			id	id
		user		user, map
			id
```

(This is needed in order to regenerate the challenge to verify a device
attestation.  XXX This should perhaps be randomized, and the
randomization included in the attestation set file.)

### Device attestation set

```
offset	length	data
0	8	`FIDOSIGA' in US-ASCII (A for `Attestation')
8	*	CBOR map of credential_id to attestation_object
*	4	zlib crc32 checksum
```

### Signature set

```
offset	length	data
0	8	`FIDOSIGS' in US-ASCII (S for `signature set')
8	*	CBOR map of credential_id to CBOR map with
		0: 24-byte randomization (byte string)
		1: authenticator_data (byte string)
			0	32	rpIdHash
			32	1	flags
			33	4	signature count
			37	*	extensions (CBOR)
		2: signature (byte string)
*	4	zlib crc32 checksum
```

Signing challenge is SHA-256 hash computed over:

```
offset	length	data
0	8	`FIDOSIGH' in US-ASCII (H for `cHallenge')
8	24	randomization
32	*	CBOR encoding of rp, relying party, map
*	*	message data
```

CRC32
-----

The CRC32 is from [RFC 1952](https://tools.ietf.org/html/rfc1952.html).
The generator polynomial is

```
G := x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11
     + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1;
```

the input bytes and output CRC both have the lsb as the highest-degree
coefficient; neither the initial nor final values are complemented; and
the CRC as an integer is stored in little-endian bytes.

Given a 32-bit quantity C representing the CRC `(m_0 x^32) mod G` for
the message so far, and given an 8-bit quantity B representing an
addendum `m_1` of degree 7, you can compute the updated CRC

```
[(m_1 + m_0 x^8) x^32] mod G
```

by:

```
C ^= B			/* C := (m_1 x^{32 - 8} + m_0 x^32) mod G */
repeat 8 times:
	/*
	 * Multiply by x and reduce modulo G:
	 *
	 *	C := [x * (m_1 x^{32 - 8 + i} + m_0 x^{32 + i})] mod G
	 *	   = (m_1 x^{32 - 8 + i + 1} + m_0 x^{32 + i + 1}) mod G
	 *
	 * The arithmetic  -(C & 1)  returns all bits zero if the
	 * highest-degree coefficient of the polynomial is zero, and
	 * all bits one if the highest-degree coefficient is one.
	 * 0xEDB88320 is  x^26 + x^23 + ... + x + 1,  which is
	 * congruent to x^32 modulo G; if multiplying by x gave us a
	 * term of x^32 then we add  x^26 + x^23 + ... + x + 1  to
	 * reduce modulo G; otherwise we add zero.
	 */
	C := (C >> 1) ^ (0xEDB88320 & -(C & 1))
/*
 * C = (m_1 x^32 + m_0 x^{32 + 8}) mod G
 *   = [(m_1 + m_0 x^8) x^32] mod G
 */
return C
```

(This is the same polynomial as in the POSIX cksum utility, but the
POSIX cksum utility interprets the input bytes, and yields an output
CRC, in reverse bit order from zlib; POSIX cksum also implicitly
appends the length of the input in little-endian bytes.)
