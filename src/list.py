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


from ._data import Header
from ._data import attset_decode
from ._data import credset_decode


def listcreds(blob):
    if len(blob) < 8:
        raise Exception('file too small')
    header = blob[0:8]
    if header == Header.CREDSET:
        return sorted(credset_decode(blob).keys())
    elif header == Header.ATTSET:
        return sorted(attset_decode(blob).keys())
    elif header == Header.SIGSET or header == Header.SIGNEDMSG:
        raise Exception('do not list signatories without verifying them')
    elif header == Header.SOFTKEY:
        raise Exception('softkeys do not store credentials')
    else:
        raise Exception('unknown file type')
