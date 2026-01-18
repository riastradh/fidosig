# -*- coding: utf-8 -*-

#  Copyright 2020-2026 Taylor R Campbell
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


from ._clientdata import ClientData

try:
    # >=2.0
    from fido2.client import Fido2Client as Fido2Client_v2
    from fido2.client import DefaultClientDataCollector
    from fido2.webauthn import AuthenticationExtensionsClientOutputs
    from fido2.webauthn import AuthenticationResponse
    from fido2.webauthn import AuthenticatorAssertionResponse
    from fido2.webauthn import AuthenticatorAttachment
    from fido2.webauthn import AuthenticatorAttestationResponse
    from fido2.webauthn import PublicKeyCredentialType
    from fido2.webauthn import RegistrationResponse

    class webauthn_json_mapping:
        enabled = True

    class LegacyClientDataCollector(DefaultClientDataCollector):
        def collect_client_data(self, options):
            rp_id = self.get_rp_id(options, self._origin)
            self.verify_rp_id(rp_id, self._origin)
            return (
                ClientData.create(
                    type=self.get_request_type(options),
                    origin=self._origin,
                    challenge=options.challenge,
                ),
                rp_id,
            )

    class Fido2Client(Fido2Client_v2):
        def __init__(self, dev, origin, verify, user_interaction=None):
            cdc = LegacyClientDataCollector(origin=origin, verify=verify)
            return super(Fido2Client, self).__init__(
                dev,
                cdc,
                user_interaction=user_interaction,
            )

    def register_complete(
            server, state, credential_id, client_data, attestation_object
    ):
        client_extension_results = AuthenticationExtensionsClientOutputs({})
        response = RegistrationResponse(
            raw_id=credential_id,
            response=AuthenticatorAttestationResponse(
                client_data=client_data,
                attestation_object=attestation_object,
            ),
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            client_extension_results=client_extension_results,
            type=PublicKeyCredentialType.PUBLIC_KEY,
        )
        return server.register_complete(state, response=response)

    def authenticate_complete(
            server, state, credentials, credential_id, client_data, auth_data,
            signature,
    ):
        client_extension_results = AuthenticationExtensionsClientOutputs({})
        response = AuthenticationResponse(
            raw_id=credential_id,
            response=AuthenticatorAssertionResponse(
                client_data=client_data,
                authenticator_data=auth_data,
                signature=signature,
                user_handle=None,
            ),
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            client_extension_results=client_extension_results,
            type=PublicKeyCredentialType.PUBLIC_KEY,
        )
        return server.authenticate_complete(
            state,
            credentials,
            response,
        )

except ImportError:
    # <2.0

    from fido2.client import Fido2Client

    try:
        # >=0.9
        import fido2.features
        webauthn_json_mapping = fido2.features.webauthn_json_mapping
    except ImportError:
        # <0.9
        class webauthn_json_mapping:
            enabled = False

    def register_complete(
            server, state, credential_id, client_data, attestation_object
    ):
        return server.register_complete(state, client_data, attestation_object)

    def authenticate_complete(
            server, state, credentials, credential_id, client_data, auth_data,
            signature,
    ):
        return server.authenticate_complete(
            state,
            credentials,
            credential_id,
            client_data,
            auth_data,
            signature,
        )

Fido2Client = Fido2Client       # export
