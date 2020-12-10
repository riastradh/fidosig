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
from ._data import attset_encode
from ._data import credset_decode
from ._data import credset_encode
from ._data import sigset_decode
from ._data import sigset_encode


def merge(blobs):
    if len(blobs) == 0:
        raise Exception('no blobs to merge')
    blob = blobs[0]
    if len(blob) < 8:
        raise Exception('file too small')
    header = blob[0:8]
    if header == Header.CREDSET:
        return credset_encode(_merge(map(credset_decode, blobs)))
    elif header == Header.ATTSET:
        return attset_encode(_merge(map(attset_decode, blobs)))
    elif header == Header.SIGSET:
        return sigset_encode(_merge(map(sigset_decode, blobs)))
    else:
        raise Exception('unknown file type')


def _merge(dicts):
    # XXX check for collisions and warn about them
    return {k: v for d in dicts for k, v in d.items()}
