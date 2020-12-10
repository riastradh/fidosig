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
import threading

from fido2.client import Fido2Client
from fido2.ctap2 import AttestedCredentialData
from fido2.hid import STATUS
from fido2.webauthn import PublicKeyCredentialDescriptor
from fido2.webauthn import PublicKeyCredentialType
from fido2.webauthn import UserVerificationRequirement

from ._data import SIGENTRY
from ._data import credset_decode
from ._data import sigset_decode
from ._data import sigset_encode
from ._iterdevs import iterdevs
from ._proto import fidosig_origin
from ._proto import sign_challenge
from ._proto import sign_server
from ._proto import verify_origin


def sign(
        rp, credset, msg, sigset=None, header=None, randomization=None,
        prompt=None
):
    credset_dict = credset_decode(credset)
    sigset_dict = {} if sigset is None else sigset_decode(sigset)
    if header is None:
        header = b''
    assert isinstance(header, bytes)    # bytes, not Unicode text
    if randomization is None:
        randomization = os.urandom(24)

    server = sign_server(rp)
    challenge = sign_challenge(randomization, header, msg)
    descriptors = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=credential_id,
        )
        for credential_id in sorted(credset_dict.keys())
    ]

    request_options, state = server.authenticate_begin(
        credentials=descriptors,
        user_verification=UserVerificationRequirement.DISCOURAGED,
        challenge=challenge,
    )

    lock = threading.Lock()
    prompted = [False]

    def on_keepalive(status):
        if status == STATUS.UPNEEDED:
            done = False
            with lock:
                done = prompted[0]
                prompted[0] = True
            if not done:
                prompt()

    def per_device(dev, cancel_ev=None):
        client = Fido2Client(dev, fidosig_origin(rp['id']), verify_origin)
        return client.get_assertion(
            request_options['publicKey'],
            on_keepalive=on_keepalive if prompt is not None else None,
            **({} if cancel_ev is None else {'event': cancel_ev})
        )

    assertions, client_data = iterdevs(per_device)
    assert len(assertions) >= 1

    for assertion in assertions:
        credential_id = assertion.credential['id']
        auth_data = assertion.auth_data
        signature = assertion.signature

        # Verify the signature before we return it.
        if credential_id not in credset_dict:
            raise Exception('unknown credential')
        credentials = [AttestedCredentialData.create(
            b'\0' * 16, credential_id, credset_dict[credential_id],
        )]
        server.authenticate_complete(
            state,
            credentials,
            credential_id,
            client_data,
            auth_data,
            signature,
        )

        # XXX Warn if we're overwriting?
        sigset_dict[credential_id] = {
            SIGENTRY.RANDOMIZATION: randomization,
            SIGENTRY.AUTH_DATA: assertions[0].auth_data,
            SIGENTRY.SIGNATURE: assertions[0].signature,
        }

    return sigset_encode(sigset_dict)
