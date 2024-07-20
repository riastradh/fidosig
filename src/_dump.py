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


import struct

from ._crc import crc32
from ._data import Header
from ._data import SIGENTRY
from ._data import attset_decode
from ._data import credid_externalize
from ._data import credset_decode
from ._data import signedmsg_decode
from ._data import sigset_decode


def dump(blob, f):
    if len(blob) < 8:
        f.write('truncated\n')
        return
    stored_checksum = struct.unpack('<I', blob[-4:])[0]
    computed_checksum = crc32(blob[:-4]) & 0xffffffff
    if stored_checksum != computed_checksum:
        f.write('invalid checksum\n')
        return
    header = blob[0:8]
    if header == Header.CREDSET:
        _dump_credset(blob, f)
    elif header == Header.ATTSET:
        _dump_attset(blob, f)
    elif header == Header.SIGNEDMSG:
        _dump_signedmsg(blob, f)
    elif header == Header.SIGSET:
        _dump_sigset(blob, f)
    elif header == Header.SOFTKEY:
        _dump_softkey(blob, f)
    else:
        f.write('unknown\n')


def _dump_credset(credset, f):
    try:
        credset_dict = credset_decode(credset)
    except Exception as e:
        f.write('invalid credential set: %s\n' % (e.message,))
        return
    f.write('credential set (%u members)\n' % (len(credset_dict),))
    for credential_id, public_key in credset_dict.items():
        credidstr = credid_externalize(credential_id).decode('utf-8')
        f.write('- credential id: %s\n' % (credidstr,))
        f.write('  public key: %r\n' % (public_key,))  # XXX pretty


def _dump_attset(attset, f):
    try:
        attset_dict = attset_decode(attset)
    except Exception as e:
        f.write('invalid attestation set: %s\n' % (e.message,))
        return
    f.write('attestation set (%u members)\n' % (len(attset_dict),))
    for credential_id, attestation_object in attset_dict.items():
        credidstr = credid_externalize(credential_id).decode('utf-8')
        f.write('- credential id: %s\n' % (credidstr,))
        f.write('  attestation: %r\n' % (attestation_object,))  # XXX pretty


def _dump_sigset(sigset, f):
    try:
        sigset_dict = sigset_decode(sigset)
    except Exception as e:
        f.write('invalid signature set: %s\n' % (e.message,))
        return
    n = len(sigset_dict)
    f.write(
        'signature set (%u alleged signer%s)\n' % (n, "" if n == 1 else "s")
    )
    _dump_signatures(sigset_dict, f)


def _dump_signedmsg(signedmsg, f):
    try:
        sigset_dict, msg = signedmsg_decode(signedmsg)
    except Exception as e:
        f.write('invalid signed msg: %s\n' % (e.message,))
        return
    n = len(sigset_dict)
    f.write(
        'signed mesage (%u alleged signer%s)\n' % (n, "" if n == 1 else "s")
    )
    f.write('  UNVERIFIED message: %r\n' % (msg,))  # XXX truncate or something
    _dump_signatures(sigset_dict, f)


def _dump_signatures(sigset_dict, f):
    for credential_id, sigentry in sigset_dict.items():
        credidstr = credid_externalize(credential_id).decode('utf-8')
        f.write('- alleged signer %s\n' % (credidstr,))
        if randomization := sigentry.get(SIGENTRY.RANDOMIZATION):
            f.write('  randomization: %s\n' % (randomization.hex(),))
            del sigentry[SIGENTRY.RANDOMIZATION]
        else:
            f.write('  missing randomization\n')
        if auth_data := sigentry.get(SIGENTRY.AUTH_DATA):
            f.write('  auth data: %s\n' % (auth_data.hex(),))
            del sigentry[SIGENTRY.AUTH_DATA]
        else:
            f.write('  missing auth data\n')
        if signature := sigentry.get(SIGENTRY.SIGNATURE):
            f.write('  signature: %s\n' % (signature.hex(),))
            del sigentry[SIGENTRY.SIGNATURE]
        else:
            f.write('  missing signature\n')
        for key, value in sorted(sigentry.items()):
            f.write('  unknown %r: %r\n' % (key, value))


def _dump_softkey(softkey, f):
    # XXX print version number
    f.write('software fidosig key\n')
