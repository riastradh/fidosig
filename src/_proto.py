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


from hashlib import sha256

from fido2 import cbor
from fido2.server import Fido2Server
from fido2.webauthn import AttestationConveyancePreference


SCHEME = 'fidosig'


def fidosig_origin(rp_id):
    return 'fidosig://' + rp_id


def verify_origin(rp_id, origin):
    # In the server/client and host/device interactions, we control the
    # server, client, and host roles alike, so the origin returned by
    # the client to the server should always be what fidosig_origin
    # returns; any mismatch here implies some internal bug in fidosig.
    if origin != fidosig_origin(rp_id):
        raise Exception('Internal error: fidosig origin and rpid mismatch')
    return True


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
