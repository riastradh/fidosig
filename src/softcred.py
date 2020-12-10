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

from fido2 import cbor
from fido2 import cose

from ._data import credset_decode
from ._data import credset_encode
from ._data import softkey_decode
from .softkey import softkey_derive_ed25519priv


def softcred(softkey, rp, user, credset=None):
    seed = softkey_decode(softkey)
    credset_dict = {} if credset is None else credset_decode(credset)

    credseed = os.urandom(32)
    credinput = cbor.encode({'rp': rp, 'user': user})
    credtoken = hmac.digest(credseed, credinput, sha256)
    credential_id = credtoken + hmac.digest(seed, credtoken, sha256)
    assert len(credential_id) == 64

    ed25519_privkey = softkey_derive_ed25519priv(seed, credential_id)
    ed25519_pubkey = ed25519_privkey.public_key()

    public_key = cose.EdDSA.from_cryptography_key(ed25519_pubkey)

    if credential_id in credset_dict:
        raise Exception('Duplicate credential id')
    credset_dict[credential_id] = public_key

    # XXX Some kind of attestation of rp/user, at least?  I.e., prove
    # that the owner of the private key accepted this rp and user,
    # e.g. by signing a message involving them.
    return credset_encode(credset_dict)
