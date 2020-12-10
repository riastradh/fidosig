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


import hmac
import os

from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fido2 import cbor

from ._data import softkey_encode


def softkeygen():
    seed = os.urandom(32)
    return softkey_encode(seed)


def softkey_valid_credential_id(seed, credential_id):
    assert isinstance(seed, bytes)
    assert len(seed) == 32
    assert isinstance(credential_id, bytes)
    assert len(credential_id) == 64
    return credential_id[32:] == hmac.digest(seed, credential_id[:32], sha256)


def softkey_derive_ed25519priv(seed, credential_id):
    assert softkey_valid_credential_id(seed, credential_id)
    h = hmac.new(seed, digestmod=sha256)
    h.update(cbor.encode(b'ed25519'))   # defend against algorithmic agility
    h.update(credential_id)
    return Ed25519PrivateKey.from_private_bytes(h.digest())
