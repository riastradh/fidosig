# -*- coding: utf-8 -*-

#  Copyright 2023 Taylor R Campbell
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
            # XXX This must be canonicalized into the particular form
            # used by Python json.dumps as called by python-fido2<0.9.
            # In particular, this must guarantee a particular order of
            # entries.  Otherwise, older signers and newer verifiers,
            # or vice versa, may disagree!
            return cls(json.dumps(kwargs).encode())

    class WEBAUTHN_TYPE:
        MAKE_CREDENTIAL = CollectedClientData.TYPE.CREATE
        GET_ASSERTION = CollectedClientData.TYPE.GET
except ImportError:             # <0.9
    from fido2.client import ClientData
    from fido2.client import WEBAUTHN_TYPE


ClientData = ClientData
WEBAUTHN_TYPE = WEBAUTHN_TYPE
