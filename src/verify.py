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


from fido2.attestation import InvalidSignature
try:                            # >=0.9
    from fido2.webauthn import AttestedCredentialData
    from fido2.webauthn import AuthenticatorData
    from fido2.webauthn import CollectedClientData

    class ClientData(CollectedClientData):
        @classmethod
        def build(cls, **kwargs):
            import json
            if 'cross_origin' in kwargs:
                assert 'crossOrigin' not in kwargs
                kwargs['crossOrigin'] = kwargs['cross_origin']
                del kwargs['cross_origin']
            return cls(json.dumps(kwargs).encode())

    class WEBAUTHN_TYPE:
        MAKE_CREDENTIAL = CollectedClientData.TYPE.CREATE
        GET_ASSERTION = CollectedClientData.TYPE.GET
except ImportError:             # <0.9
    from fido2.client import ClientData
    from fido2.client import WEBAUTHN_TYPE
    from fido2.ctap2 import AttestedCredentialData
    from fido2.ctap2 import AuthenticatorData
from fido2.utils import websafe_encode
from fido2.webauthn import UserVerificationRequirement

from ._data import SIGENTRY
from ._data import credset_decode
from ._data import sigset_decode
from ._proto import fidosig_origin
from ._proto import sign_challenge
from ._proto import sign_server


def verify(rp, credset, msg, sigset, header=None):
    credset_dict = credset_decode(credset)
    sigset_dict = sigset_decode(sigset)
    if header is None:
        header = b''
    assert isinstance(header, bytes)    # bytes, not Unicode text
    return set(
        credential_id
        for credential_id, sig in sigset_dict.items()
        if credential_id in credset_dict
        if _verify_1(
            rp, header, msg, credential_id, credset_dict[credential_id], sig
        )
    )


def _verify_1(rp, header, msg, credential_id, public_key, sig):
    randomization = sig[SIGENTRY.RANDOMIZATION]
    auth_data = AuthenticatorData(sig[SIGENTRY.AUTH_DATA])
    signature = sig[SIGENTRY.SIGNATURE]

    server = sign_server(rp)
    challenge = sign_challenge(randomization, header, msg)

    request_options, state = server.authenticate_begin(
        user_verification=UserVerificationRequirement.DISCOURAGED,
        challenge=challenge,
    )

    client_data = ClientData.build(
        type=WEBAUTHN_TYPE.GET_ASSERTION,
        origin=fidosig_origin(rp['id']),
        challenge=websafe_encode(challenge),
        clientExtensions={},
    )

    credentials = [AttestedCredentialData.create(
        b'\0' * 16, credential_id, public_key
    )]

    try:
        server.authenticate_complete(
            state,
            credentials,
            credential_id,
            client_data,
            auth_data,
            signature,
        )
    except InvalidSignature:
        return False
    return True
