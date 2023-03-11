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


try:
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
except ImportError:
    from fido2.client import ClientData
    from fido2.client import WEBAUTHN_TYPE
from fido2.utils import websafe_encode

from ._data import attset_decode
from ._data import credset_decode
from ._proto import cred_challenge
from ._proto import cred_server
from ._proto import fidosig_origin


def attest(rp, user, credset, attset):
    credset_dict = credset_decode(credset)
    attset_dict = attset_decode(attset)

    server = cred_server(rp)
    challenge = cred_challenge(rp, user)

    create_options, state = server.register_begin(user, challenge=challenge)

    client_data = ClientData.build(
        type=WEBAUTHN_TYPE.MAKE_CREDENTIAL,
        origin=fidosig_origin(rp['id']),
        challenge=websafe_encode(challenge),
        clientExtensions={},
    )

    for credential_id, public_key in credset_dict.items():
        if credential_id not in attset_dict:
            raise Exception('Missing attestation')
        attestation_object = attset_dict[credential_id]
        auth_data = server.register_complete(
            state, client_data, attestation_object
        )
        if auth_data.credential_data.credential_id != credential_id:
            raise Exception('Wrong credential id')
        if auth_data.credential_data.public_key != public_key:
            raise Exception('Wrong public key')
