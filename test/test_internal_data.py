# -*- coding: utf-8 -*-

#  Copyright 2024 Taylor R Campbell
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


import pytest

from fidosig._data import _encap
from fidosig._data import _decap
from fidosig._data import _encapextra
from fidosig._data import _decapextra


def flipbit(bit, buf):
    n = len(buf)
    buf1 = (int.from_bytes(buf) ^ (1 << bit)).to_bytes(n)
    assert len(buf) == len(buf1)
    return buf1


def test_encapdecap():
    header = b'FROTZ'
    obj = {42: 'mumble'}
    blob = _encap(header, obj)
    assert blob == b'FROTZ\xa1\x18*fmumble\x05w\xa3\xe4'
    obj1 = _decap(header, blob, 'frobnitz')
    assert obj1 == obj
    assert _encap(header, obj1) == blob
    badblob = blob + b'\x00'                    # append garbage
    with pytest.raises(Exception):
        _decap(header, badblob, 'frobnitz')
    badblob = flipbit(0, blob)                  # flip bit in header
    with pytest.raises(Exception):
        _decap(header, badblob, 'frobnitz')
    badblob = flipbit(8*len(header), blob)      # flip bit at start of object
    with pytest.raises(Exception):
        _decap(header, badblob, 'frobnitz')
    badblob = flipbit(8*len(blob) - 33, blob)   # flip bit at end of object
    with pytest.raises(Exception):
        _decap(header, badblob, 'frobnitz')
    badblob = flipbit(8*len(blob) - 1, blob)    # flip bit in checksum
    with pytest.raises(Exception):
        _decap(header, badblob, 'frobnitz')


def test_encapdecapextra():
    header = b'FROTZ'
    obj = {42: 'mumble'}
    extra = b'hello world'
    blob = _encapextra(header, obj, extra)
    assert blob == b'FROTZ\xa1\x18*fmumblehello world\x94\xb6;\xb2'
    with pytest.raises(Exception):
        _decap(header, blob, 'frobnitz')
    obj1, extra1 = _decapextra(header, blob, 'frobnitz')
    assert obj1 == obj
    assert extra1 == extra
    assert _encapextra(header, obj1, extra1) == blob
    badblob = blob + b'\x00'                    # append garbage
    with pytest.raises(Exception):
        _decapextra(header, badblob, 'frobnitz')
    badblob = flipbit(0, blob)                  # flip bit in header
    with pytest.raises(Exception):
        _decapextra(header, badblob, 'frobnitz')
    badblob = flipbit(8*len(header), blob)      # flip bit in object
    with pytest.raises(Exception):
        _decapextra(header, badblob, 'frobnitz')
    badblob = flipbit(8*len(blob) - 33, blob)   # flip bit in extra
    with pytest.raises(Exception):
        _decapextra(header, badblob, 'frobnitz')
    badblob = flipbit(8*len(blob) - 1, blob)    # flip bit in checksum
    with pytest.raises(Exception):
        _decapextra(header, badblob, 'frobnitz')
