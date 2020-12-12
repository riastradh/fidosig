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


import six

from hashlib import sha256
from six.moves.urllib.parse import urlparse

from fido2 import cbor
from fido2.server import Fido2Server
from fido2.webauthn import AttestationConveyancePreference

from ._pubsuffix import public_suffixes


SCHEME = 'fidosig'


def fidosig_origin(rp_id):
    return 'fidosig://' + rp_id


def verify_origin(rp_id, origin):
    # Derived from fido2.rpid.verify_rp_id.
    if isinstance(rp_id, six.binary_type):
        rp_id = rp_id.decode()
    if not rp_id:
        return False
    if isinstance(origin, six.binary_type):
        origin = origin.decode()

    url = urlparse(origin)
    if url.scheme != SCHEME:
        return False
    if url.hostname == rp_id:
        return True
    if url.hostname.endswith('.' + rp_id) and rp_id not in public_suffixes:
        return True
    return False


def rp_origin_verifier(rp_id):
    return lambda origin: verify_origin(rp_id, origin)


class Challenge:
    # Avoid collisions with Header in data.py.
    CRED = b'FIDOSIGU'          # `user'
    SIGN = b'FIDOSIGH'          # `challenge'


def cred_server(rp):
    return Fido2Server(
        rp,
        attestation=AttestationConveyancePreference.DIRECT,
        verify_origin=rp_origin_verifier(rp['id']),
    )


def cred_challenge(rp, user):
    h = sha256()
    h.update(Challenge.CRED)
    h.update(cbor.encode({'rp': rp, 'user': user}))
    return h.digest()


def sign_server(rp):
    return Fido2Server(
        rp,
        attestation=AttestationConveyancePreference.DIRECT,
        verify_origin=rp_origin_verifier(rp['id']),
    )


# XXX Would be nice to incorporate the credential id and public key
# here, but we can't.  At least with Ed25519 the public key is
# incorporated.
#
# Not necessary to include the relying party id because that is already
# included via the client data.
#
def sign_challenge(randomization, header, msg):
    assert len(randomization) == 24
    h = sha256()
    h.update(Challenge.SIGN)
    h.update(randomization)
    h.update(cbor.encode(header))
    h.update(msg)
    return h.digest()
