# -*- coding: utf-8 -*-

#  Copyright 2020 Taylor R Campbell
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


import base64
import struct

from fido2 import cbor
try:
    from fido2.webauthn import AttestationObject
except ImportError:
    from fido2.ctap2 import AttestationObject

from ._crc import crc16
from ._crc import crc32


class Header:
    # Avoid collisions with Challenge in proto.py.
    CREDSET = b'FIDOSIGC'
    ATTSET = b'FIDOSIGA'
    SIGSET = b'FIDOSIGS'
    SOFTKEY = b'FIDOSIGK'


def _encap(header, obj):
    payload = cbor.encode(obj)
    checksum = crc32(header + payload) & 0xffffffff
    return header + payload + struct.pack('<I', checksum)


def _decap(header, blob, typename):
    if not blob.startswith(header) or \
       len(blob) < len(header) + 4:
        raise Exception('Invalid %s' % (typename,))
    stored_checksum = struct.unpack('<I', blob[-4:])[0]
    computed_checksum = crc32(blob[:-4]) & 0xffffffff
    if stored_checksum != computed_checksum:
        raise Exception('Checksum failure in %s' % (typename,))
    return cbor.decode(blob[len(header):-4])


def credset_encode(credset_dict):
    assert isinstance(credset_dict, dict)
    return _encap(Header.CREDSET, credset_dict)


def credset_decode(credset):
    credset_dict = _decap(Header.CREDSET, credset, 'credential set')
    if not isinstance(credset_dict, dict):
        raise Exception('Invalid credential set')
    # XXX validate schema
    return credset_dict


def attset_encode(attset_dict):
    assert isinstance(attset_dict, dict)

    def encode_ao(ao):
        if hasattr(AttestationObject, 'KEY'):  # <0.9
            return bytes(ao)
        else:                   # >=0.9
            return cbor.encode({
                1: ao.fmt,
                2: ao.auth_data,
                3: ao.att_stmt,
            })

    return _encap(Header.ATTSET, {
        credential_id: encode_ao(attestation_object)
        for credential_id, attestation_object in attset_dict.items()
    })


def attset_decode(attset):
    obj = _decap(Header.ATTSET, attset, 'attestation set')
    if not isinstance(obj, dict):
        raise Exception('Invalid attestation set')

    def decode_ao(ao_bytes):
        if hasattr(AttestationObject, 'KEY'):  # <0.9
            return AttestationObject(ao_bytes)
        else:                   # >=0.9
            numeric = cbor.decode(ao_bytes)
            nominal = {
                'fmt': numeric[1],
                'authData': numeric[2],
                'attStmt': numeric[3],
            }
            return AttestationObject(cbor.encode(nominal))

    # XXX validate schema
    return {
        credential_id: decode_ao(ao_bytes)
        for credential_id, ao_bytes in obj.items()
    }


def sigset_encode(sigset_dict):
    assert isinstance(sigset_dict, dict)
    return _encap(Header.SIGSET, sigset_dict)


def sigset_decode(sigset):
    sigset_dict = _decap(Header.SIGSET, sigset, 'signature set')
    if not isinstance(sigset_dict, dict):
        raise Exception('Invalid signature set')
    # XXX validate schema
    return sigset_dict


class SIGENTRY:
    RANDOMIZATION = 0
    AUTH_DATA = 1
    SIGNATURE = 2


def softkey_encode(seed):
    assert isinstance(seed, bytes)
    assert len(seed) == 32
    softkey_dict = {
        0: 1,                   # version number
        1: seed,
    }
    return _encap(Header.SOFTKEY, softkey_dict)


def softkey_decode(softkey):
    softkey_dict = _decap(Header.SOFTKEY, softkey, 'software key')
    if not isinstance(softkey_dict, dict) or \
       0 not in softkey_dict or \
       softkey_dict[0] != 1:
        raise Exception('Invalid software key')
    seed = softkey_dict[1]
    assert isinstance(seed, bytes)
    assert len(seed) == 32
    return seed


def credid_externalize(credential_id):
    assert isinstance(credential_id, bytes)
    data = credential_id + struct.pack('<H', crc16(credential_id))
    assert crc16(data) == 0
    return base64.urlsafe_b64encode(data)


def credid_internalize(extcredid):
    data = base64.urlsafe_b64decode(extcredid)
    if len(data) < 2 or crc16(data):
        raise Exception('Checksum failure')
    return data[:-2]
