# -*- coding: utf-8 -*-

#  Copyright 2020-2023 Taylor R Campbell
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


import threading

import fido2.client

from fido2.client import Fido2Client
from fido2.hid import STATUS
from fido2.webauthn import PublicKeyCredentialDescriptor
from fido2.webauthn import PublicKeyCredentialType

from ._data import attset_decode
from ._data import attset_encode
from ._data import credset_decode
from ._data import credset_encode
from ._iterdevs import iterdevs
from ._proto import cred_challenge
from ._proto import cred_server
from ._proto import fidosig_origin
from ._proto import verify_origin


def cred(rp, user, credset=None, attset=None, prompt=None):
    assert set(['id', 'name']) <= set(rp.keys()) <= set(['id', 'name', 'icon'])
    assert set(['id', 'name']) <= set(user.keys())
    assert set(user.keys()) <= set(['id', 'name', 'icon', 'display_name'])
    assert isinstance(user['id'], bytes)
    credset_dict = {} if credset is None else credset_decode(credset)
    attset_dict = {} if attset is None else attset_decode(attset)

    server = cred_server(rp)
    challenge = cred_challenge(rp, user)
    create_options, state = server.register_begin(
        user,
        credentials=[
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=credential_id,
            )
            for credential_id in sorted(credset_dict.keys())
        ],
        challenge=challenge,
    )

    lock = threading.Lock()
    prompted = [False]

    def prompt_up():
        done = False
        with lock:
            done = prompted[0]
            prompted[0] = True
        if not done:
            prompt()

    def per_device(dev, cancel_ev=None):
        if hasattr(fido2.client, 'UserInteraction'):
            # >=0.9
            class UserInteraction(fido2.client.UserInteraction):
                def prompt_up(self):
                    prompt_up()

                def request_pin(self, *args, **kwargs):
                    return None         # XXX pin

                def request_uv(self, *args, **kwargs):
                    return True

            client = Fido2Client(
                dev, fidosig_origin(rp['id']), verify_origin,
                user_interaction=UserInteraction()
            )
            attresponse = client.make_credential(
                create_options['publicKey'],
                **({} if cancel_ev is None else {'event': cancel_ev})
            )
            return attresponse.attestation_object, attresponse.client_data
        else:
            # <0.9
            def on_keepalive(status):
                if status == STATUS.UPNEEDED:
                    prompt_up()

            client = Fido2Client(dev, fidosig_origin(rp['id']), verify_origin)
            return client.make_credential(
                create_options['publicKey'],
                on_keepalive=on_keepalive if prompt is not None else None,
                **({} if cancel_ev is None else {'event': cancel_ev})
            )

    attestation_object, client_data = iterdevs(per_device)
    auth_data = server.register_complete(
        state,
        client_data,
        attestation_object,
    )

    credential_id = auth_data.credential_data.credential_id
    public_key = auth_data.credential_data.public_key

    # XXX Check rather than assert?  Overwrite?
    if credential_id in credset_dict or credential_id in attset_dict:
        raise Exception('Duplicate credential id')
    credset_dict[credential_id] = public_key
    attset_dict[credential_id] = attestation_object
    return credset_encode(credset_dict), attset_encode(attset_dict)
