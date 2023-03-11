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


import os

from hashlib import sha256

try:                            # >=0.9
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
from fido2.ctap2 import AssertionResponse
try:
    from fido2.features import webauthn_json_mapping
except ImportError:
    class webauthn_json_mapping:
        enabled = False
try:                            # >=0.9
    from fido2.webauthn import AuthenticatorData
except ImportError:             # <0.9
    from fido2.ctap2 import AuthenticatorData
from fido2.utils import websafe_encode
from fido2.utils import websafe_decode
from fido2.webauthn import PublicKeyCredentialDescriptor
from fido2.webauthn import PublicKeyCredentialType
from fido2.webauthn import UserVerificationRequirement

from ._data import SIGENTRY
from ._data import credset_decode
from ._data import sigset_decode
from ._data import sigset_encode
from ._data import softkey_decode
from ._proto import fidosig_origin
from ._proto import sign_challenge
from ._proto import sign_server
from .softkey import softkey_derive_ed25519priv
from .softkey import softkey_valid_credential_id


def softsign(
        softkey, rp, credset, msg, sigset=None, header=None,
        randomization=None, prompt=None
):
    seed = softkey_decode(softkey)
    credset_dict = credset_decode(credset)
    sigset_dict = {} if sigset is None else sigset_decode(sigset)
    if header is None:
        header = b''
    assert isinstance(header, bytes)    # bytes, not Unicode text
    if randomization is None:
        randomization = os.urandom(24)

    def map_credential_id(credential_id):
        if webauthn_json_mapping.enabled:
            return websafe_decode(credential_id)
        else:
            return credential_id

    credential_ids = [
        credential_id
        for credential_id in sorted(credset_dict.keys())
        if softkey_valid_credential_id(seed, credential_id)
    ]
    if len(credential_ids) == 0:
        raise FileNotFoundError

    server = sign_server(rp)
    challenge = sign_challenge(randomization, header, msg)
    descriptors = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=credential_id,
        )
        for credential_id in credential_ids
    ]

    request_options, state = server.authenticate_begin(
        credentials=descriptors,
        user_verification=UserVerificationRequirement.DISCOURAGED,
        challenge=challenge,
    )

    assertions, client_data = \
        _get_assertions(seed, rp, request_options['publicKey'])
    assert len(assertions) == len(credential_ids)

    for credential_id, assertion in zip(credential_ids, assertions):
        # XXX Warn if we're overwriting?
        sigset_dict[credential_id] = {
            SIGENTRY.RANDOMIZATION: randomization,
            SIGENTRY.AUTH_DATA: assertion.auth_data,
            SIGENTRY.SIGNATURE: assertion.signature,
        }

    return sigset_encode(sigset_dict)


def _get_assertions(seed, rp, options):
    if webauthn_json_mapping.enabled:
        challenge = options['challenge']
    else:
        challenge = websafe_encode(options['challenge'])
    client_data = ClientData.build(
        type=WEBAUTHN_TYPE.GET_ASSERTION,
        origin=fidosig_origin(rp['id']),
        challenge=challenge,
        clientExtensions={},
    )
    client_data_hash = client_data.hash
    rp_id_hash = sha256(rp['id'].encode('utf8')).digest()
    if hasattr(options, 'allow_credentials'):  # <0.9
        allow_credentials = options.allow_credentials
    else:                       # >=0.9
        allow_credentials = options['allowCredentials']
    assertions = [
        _get_assertion_1(seed, rp_id_hash, descriptor, client_data_hash)
        for descriptor in allow_credentials
    ]
    return assertions, client_data


def _get_assertion_1(seed, rp_id_hash, descriptor, client_data_hash):
    if hasattr(descriptor, 'id'):  # <0.9
        credential_id = descriptor.id
    else:                       # >=0.9
        if webauthn_json_mapping.enabled:
            credential_id = websafe_decode(descriptor['id'])
        else:
            credential_id = descriptor['id']
    assert softkey_valid_credential_id(seed, credential_id)
    auth_data = AuthenticatorData.create(
        rp_id_hash=rp_id_hash,
        flags=AuthenticatorData.FLAG.USER_PRESENT,
        counter=0xdeadbeef,
    )
    ed25519priv = softkey_derive_ed25519priv(seed, credential_id)
    signature = ed25519priv.sign(auth_data + client_data_hash)
    if hasattr(AssertionResponse, 'from_dict'):  # >=0.9
        return AssertionResponse(descriptor, auth_data, signature)
    else:                       # <0.9
        return AssertionResponse.create(descriptor, auth_data, signature)
