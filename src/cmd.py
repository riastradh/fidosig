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


import getopt
import json
import os


from ._data import credid_externalize
from ._dump import dump
from .attest import attest
from .cred import cred
from .list import listcreds
from .merge import merge
from .sign import inlinesign
from .sign import sign
from .softcred import softcred
from .softkey import softkeygen
from .softsign import softsign
from .verify import inlineverify
from .verify import verify


progname = None


def cmd(argv, stdin, stdout, stderr):
    global progname
    progname = argv[0]
    progname_slash = progname.rfind('/')
    if progname_slash != -1:
        progname = progname[progname_slash + 1:]
    if len(argv) <= 1:
        usage(stderr)
        return 1
    cmd = argv[1]
    args = argv[2:]
    if cmd == 'help':
        if len(args) == 0:
            usage(stdout)
            return 0
        elif args[0] in CMDS:
            cmd = args[0]
            args = ['--help']
    if cmd not in CMDS:
        usage(stderr)
        return 1
    return CMDS[cmd](args, stdin, stdout, stderr)


def usage(out):
    out.write('Usage: %s attest <credset> <attset>\n' % (progname,))
    out.write('       %s cred [-a] <credset> [<attset>]\n' % (progname,))
    out.write('       %s inlinesign [-a] <credset> <msg> <signedmsg>\n' %
              (progname,))
    out.write('       %s inlineverify <credset> <msg> <signedmsg>\n' %
              (progname,))
    out.write('       %s list <file>\n' % (progname,))
    out.write('       %s merge [-a] <output> <inputs>...\n' % (progname,))
    out.write('       %s sign [-a] <credset> <msg> <sigset>\n' % (progname,))
    out.write('       %s softkey <softkey>\n' % (progname,))
    out.write('       %s softcred [-a] <softkey> <credset>\n' % (progname,))
    out.write('       %s softsign [-a] <softkey> <credset> <msg> <sigset>\n' %
              (progname,))
    out.write('       %s verify <sigset> <credset> [<msg>]\n' %
              (progname,))


def _get_rp(rp_id):
    if rp_id is None:
        rp_id = os.getenv('FIDOSIG_RP')
    if rp_id is None:
        raise Exception('No relying party id specified')
    return json.loads(rp_id)


def _get_user(user_id):
    if user_id is None:
        user_id = os.getenv('FIDOSIG_USER')
    if user_id is None:
        raise Exception('No user id specified')
    user = json.loads(user_id)
    user['id'] = user['id'].encode('utf-8')
    return user


def _get_header(header, msg_path, stderr):
    if header is not None:
        return os.fsencode(header)
    if msg_path != '-':
        return os.fsencode(msg_path)
    stderr.write('Warning: message on stdin, header will be empty\n')
    header = b''


def _read_file(path, stdin, append=None, maxbytes=1024 * 1024):
    def read(f):
        blob = f.read(maxbytes)
        if len(f.read(1)):
            raise Exception('File too large')
        return blob

    if path == '-':
        return read(stdin.buffer)
    try:
        f = open(path, 'rb')
    except FileNotFoundError:
        if append:
            return None
        raise
    with f:
        return read(f)


def _write_file(blob, path, stdout, append=None, maxbytes=1024 * 1024):
    assert isinstance(blob, bytes)
    if len(blob) > maxbytes:
        raise Exception('Output file too large')
    if path == '-':
        stdout.buffer.write(blob)
        return

    path_tmp = path + '.tmp'
    with open(path_tmp, 'xb') as f:
        f.write(blob)
    try:
        if append:
            os.rename(path_tmp, path)
        else:
            os.link(path_tmp, path)
            os.unlink(path_tmp)
    except Exception:
        try:
            os.unlink(path_tmp)
        except Exception:
            pass
        raise


def usage_attest(out):
    out.write('Usage: %s attest <credset> <attset>\n' % (progname,))
    out.write('\n')
    out.write('  Verify device attestations for all credentials in\n')
    out.write('  <credset>.  Fail if any credential is missing a\n')
    out.write('  valid device attestation.\n')


def cmd_attest(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'hr:u:', [
            'help',
            'rp',
            'user',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_attest(stderr)
        return 1

    rp_id = None
    user_id = None
    errors = []
    for o, a in opts:
        if o in ('-h', '--help'):
            usage_attest(stdout)
            return 0
        elif o in ('-r', '--rp'):
            if rp_id is not None:
                errors.append('duplicate rp')
                continue
            rp_id = a
        elif o in ('-u', '--user'):
            if user_id is not None:
                errors.append('duplicate user')
                continue
            user_id = a
        else:
            assert False, 'invalid option'
    if errors or len(args) != 2:
        for error in errors:
            stderr.write('%s\n' % (error,))
        usage_attest(stderr)
        return 1

    [credset_path, attset_path] = args

    rp = _get_rp(rp_id)
    user = _get_user(user_id)

    credset = _read_file(credset_path, stdin)
    attset = _read_file(attset_path, stdin)
    # XXX print errors nicely
    attest(rp, user, credset, attset)
    return 0


def usage_cred(out):
    out.write('Usage: %s cred [-a] <credset> [<attset>]\n' % (progname,))
    out.write('\n')
    out.write('  Generate a credential from a FIDO token, and\n')
    out.write('  optionally generate a device attestation.\n')
    out.write('\n')
    out.write('Options:\n')
    out.write('  -a, --append\n')
    out.write('        append to set if it is already there, else create\n')
    out.write('  -r, --rp <rpid>\n')
    out.write('        set the relying party id\n')
    out.write('  -u, --user <userid>\n')
    out.write('        set the user id\n')


def cmd_cred(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'ahr:u:', [
            'append',
            'help',
            'rp',
            'user',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_cred(stderr)
        return 1

    append = False
    rp_id = None
    user_id = None
    errors = []
    for o, a in opts:
        if o in ('-h', '--help'):
            usage_cred(stdout)
            return 0
        elif o in ('-a', '--append'):
            append = True
        elif o in ('-r', '--rp'):
            if rp_id is not None:
                errors.append('duplicate rp')
                continue
            rp_id = a
        elif o in ('-u', '--user'):
            if user_id is not None:
                errors.append('duplicate user')
                continue
            user_id = a
        else:
            assert False, 'invalid option'
    if errors or (len(args) != 1 and len(args) != 2):
        for error in errors:
            stderr.write('%s\n' % (error,))
        usage_cred(stderr)
        return 1

    credset_path = args[0]
    attset_path = args[1] if len(args) == 2 else None

    rp = _get_rp(rp_id)
    user = _get_user(user_id)

    credset = _read_file(credset_path, stdin, append=True) if append else None
    if attset_path and append:
        attset = _read_file(attset_path, stdin, append=True)
    else:
        attset = None

    prompted = [False]

    def prompt():
        stderr.write('tap key; waiting...')
        stderr.flush()
        prompted[0] = True

    try:
        try:
            credset_, attset_ = cred(
                rp, user, credset=credset, attset=attset, prompt=prompt
            )
        finally:
            if prompted[0]:
                stderr.write('\n')
                stderr.flush()
    except FileNotFoundError:
        stderr.write('no keys found\n')
        return 1

    # XXX Select only the credential we just created to verify
    # attestation -- don't just restrict it to wholly new credsets.
    if credset is None and attset is None:
        attest(rp, user, credset_, attset_)
    credset = credset_ if credset is None else merge([credset, credset_])
    attset = attset_ if attset is None else merge([attset, attset_])

    _write_file(credset, credset_path, stdout, append=append)
    if attset_path:
        _write_file(attset, attset_path, stdout, append=append)
    return 0


def usage_dump(out):
    out.write('Usage: %s dump <file>\n' % (progname,))
    out.write('\n')
    out.write('  Dump the internal structure of <file> human-readably.\n')
    out.write('\n')
    out.write('  WARNING: This is a debugging operation only.  Do not rely\n')
    out.write('  on the output, which may be controlled by an adversary and\n')
    out.write('  is not verified by %s.\n' % (progname,))
    out.write('\n')
    out.write('  WARNING: Output format is unreliable and should not be\n')
    out.write('  parsed by scripts.\n')


def cmd_dump(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'h', [
            'help',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_list(stderr)
        return 1

    for o, a in opts:
        if o in ('-h', '--help'):
            usage_list(stdout)
            return 0
        else:
            assert False, 'invalid option'
    if len(args) != 1:
        usage_list(stderr)
        return 1

    [path] = args
    blob = _read_file(path, stdin)      # XXX larger max size
    dump(blob, stdout)
    return 0


def usage_inlinesign(out):
    out.write('Usage: %s inlinesign [-a] <credset> <msg> <signedmsg>\n' %
              (progname,))
    out.write('\n')
    out.write('  Sign the message in <msg> with any credentials in\n')
    out.write("  <credset> on the user's available tokens and store the\n")
    out.write('  resulting signed message in <signedmsg>.\n')
    out.write('\n')
    out.write('  The signed message, including signatures, must be at most\n')
    out.write('  64 MB (67108864 bytes).\n')
    out.write('\n')
    out.write('  -a, --append\n')
    out.write('        append to signatures in signed message if it is\n')
    out.write('        already there, else create new signed message\n')
    out.write('  -H, --header <header>\n')
    out.write('        use <header> as header instead of file name <msg>\n')
    out.write('  -r, --rp <rpid>\n')
    out.write('        set the relying party id\n')


def cmd_inlinesign(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'ahH:r:', [
            'append',
            'header',
            'help',
            'rp',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_inlinesign(stderr)
        return 1

    append = False
    header = None
    rp_id = None
    errors = []
    for o, a in opts:
        if o in ('-h', '--help'):
            usage_inlinesign(stdout)
            return 0
        elif o in ('-a', '--append'):
            append = True
        elif o in ('-H', '--header'):
            if header is not None:
                errors.append('duplicate header')
                continue
            header = a
        elif o in ('-r', '--rp'):
            if rp_id is not None:
                errors.append('duplicate rp')
                continue
            rp_id = a
        else:
            assert False, 'invalid option'
    if errors or len(args) != 3:
        for error in errors:
            stderr.write('%s\n' % (error,))
        usage_inlinesign(stderr)
        return 1

    [credset_path, msg_path, signedmsg_path] = args

    header = _get_header(header, msg_path, stderr)
    rp = _get_rp(rp_id)

    credset = _read_file(credset_path, stdin)
    msg = _read_file(msg_path, stdin, maxbytes=64 * 1024 * 1024)
    signedmsg = \
        _read_file(signedmsg_path, stdin, append=True) if append else None

    prompted = [False]

    def prompt():
        stderr.write('tap key; waiting...')
        stderr.flush()
        prompted[0] = True

    try:
        try:
            signedmsg = inlinesign(
                rp, credset, msg, header=header, signedmsg=signedmsg,
                prompt=prompt
            )
        finally:
            if prompted[0]:
                stderr.write('\n')
                stderr.flush()
    except FileNotFoundError:
        stderr.write('no keys found\n')
        return 1

    _write_file(signedmsg, signedmsg_path, stdout, append=append)
    return 0


def usage_inlineverify(out):
    out.write('Usage: %s inlineverify <credset> <msg> <signedmsg>\n' %
              (progname,))
    out.write('\n')
    out.write('  Verify signatures in <signedmsg> and store message in\n')
    out.write('  <msg> if there is at least one signature by a credential\n')
    out.write('  in <credset> and all signatures from any credentials in\n')
    out.write('  <credset> are valid.\n')
    out.write('\n')
    out.write('  For every credential in <credset> with a valid signature\n')
    out.write('  in <signedmsg>, print its base64url-encoded credential id,\n')
    out.write('  one per line.\n')
    out.write('\n')
    out.write('  Exits with status zero only if there is at least one\n')
    out.write('  valid signature from <credset> in <sigset>.\n')
    out.write('\n')
    out.write("  <msg> MUST NOT be `-' to mean standard output.\n")
    out.write('\n')
    out.write('Options:\n')
    out.write('  -H, --header <header>\n')
    out.write('        use <header> as header instead of file name <msg>\n')
    out.write('  -r, --rp <rpid>\n')
    out.write('        set the relying party id\n')


def cmd_inlineverify(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'hH:r:', [
            'header',
            'help',
            'rp',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_inlineverify(stderr)
        return 1

    header = None
    rp_id = None
    errors = []
    for o, a in opts:
        if o in ('-h', '--help'):
            usage_inlineverify(stdout)
            return 0
        elif o in ('-H', '--header'):
            if header is not None:
                errors.append('duplicate header')
                continue
            header = a
        elif o in ('-r', '--rp'):
            if rp_id is not None:
                errors.append('duplicate rp')
                continue
            rp_id = a
        else:
            assert False, 'invalid option'
    if errors or len(args) != 3:
        for error in errors:
            stderr.write('%s\n' % (error,))
        usage_inlineverify(stderr)
        return 1

    [credset_path, msg_path, signedmsg_path] = args
    if msg_path == '-':
        stderr.write('inlineverify output must be separate file, not stdout\n')
        return 1

    header = _get_header(header, msg_path, stderr)
    rp = _get_rp(rp_id)

    credset = _read_file(credset_path, stdin)
    signedmsg = _read_file(signedmsg_path, stdin, maxbytes=64 * 1024 * 1024)
    verified, msg = inlineverify(rp, credset, signedmsg, header=header)
    if verified:
        _write_file(msg, msg_path, None, maxbytes=64 * 1024 * 1024)
        for credential_id in sorted(verified):
            extcredid = credid_externalize(credential_id)
            stdout.buffer.write(b'%s\n' % (extcredid,))
        return 0
    else:
        return 1


def usage_list(out):
    out.write('Usage: %s list <file>\n' % (progname,))
    out.write('\n')
    out.write('  List base64url-encoded credential ids in <file>,\n')
    out.write('  which may be a credential set, an attestation set,\n')
    out.write('  or a signature set.\n')


def cmd_list(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'h', [
            'help',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_list(stderr)
        return 1

    for o, a in opts:
        if o in ('-h', '--help'):
            usage_list(stdout)
            return 0
        else:
            assert False, 'invalid option'
    if len(args) != 1:
        usage_list(stderr)
        return 1

    [path] = args
    blob = _read_file(path, stdin)
    for credential_id in listcreds(blob):
        extcredid = credid_externalize(credential_id)
        stdout.buffer.write(b'%s\n' % (extcredid,))
    return 0


def usage_merge(out):
    out.write('Usage: %s merge [-a] <output> <input1> <input2> ...\n' %
              (progname,))
    out.write('\n')
    out.write('  Merge a collection of credential sets, attestation\n')
    out.write('  sets, or signature sets.  All input files must be of\n')
    out.write('  the same type.\n')
    out.write('\n')
    out.write('Options:\n')
    out.write('  -a, --append\n')
    out.write('        append to output file if already there, else create\n')


def cmd_merge(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'ah', [
            'append',
            'help',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_merge(stderr)
        return 1

    append = False
    errors = []
    for o, a in opts:
        if o in ('-h', '--help'):
            usage_merge(stdout)
            return 0
        elif o in ('-a', '--append'):
            append = True
        else:
            assert False, 'invalid option'
    if errors or len(args) < (1 if append else 2):
        for error in errors:
            stderr.write('%s\n' % (error,))
        usage_merge(stderr)
        return 1

    out_path = args[0]
    paths = args if append else args[1:]

    blobs = [_read_file(path, stdin) for path in paths]
    out_blob = merge(blobs)
    _write_file(out_blob, out_path, stdout, append=append)
    return 0


def usage_sign(out):
    out.write('Usage: %s sign [-a] <credset> <msg> <sigset>\n' % (progname,))
    out.write('\n')
    out.write('  Sign the message in <msg> with any credentials in\n')
    out.write("  <credset> on the user's available tokens and store\n")
    out.write('  the resulting signatures in <sigset>.\n')
    out.write('\n')
    out.write('  The message must be at most 64 MB (67108864 bytes).\n')
    out.write('\n')
    out.write('Options:\n')
    out.write('  -a, --append\n')
    out.write('        append to set if it is already there, else create\n')
    out.write('  -H, --header <header>\n')
    out.write('        use <header> as header instead of file name <msg>\n')
    out.write('  -r, --rp <rpid>\n')
    out.write('        set the relying party id\n')


def cmd_sign(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'ahH:r:', [
            'append',
            'header',
            'help',
            'rp',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_sign(stderr)
        return 1

    append = False
    header = None
    rp_id = None
    errors = []
    for o, a in opts:
        if o in ('-h', '--help'):
            usage_sign(stdout)
            return 0
        elif o in ('-a', '--append'):
            append = True
        elif o in ('-H', '--header'):
            if header is not None:
                errors.append('duplicate header')
                continue
            header = a
        elif o in ('-r', '--rp'):
            if rp_id is not None:
                errors.append('duplicate rp')
                continue
            rp_id = a
        else:
            assert False, 'invalid option'
    if errors or len(args) != 3:
        for error in errors:
            stderr.write('%s\n' % (error,))
        usage_sign(stderr)
        return 1

    [credset_path, msg_path, sigset_path] = args

    header = _get_header(header, msg_path, stderr)
    rp = _get_rp(rp_id)

    credset = _read_file(credset_path, stdin)
    msg = _read_file(msg_path, stdin, maxbytes=64 * 1024 * 1024)
    sigset = _read_file(sigset_path, stdin, append=True) if append else None

    prompted = [False]

    def prompt():
        stderr.write('tap key; waiting...')
        stderr.flush()
        prompted[0] = True

    try:
        try:
            sigset = sign(
                rp, credset, msg, header=header, sigset=sigset, prompt=prompt
            )
        finally:
            if prompted[0]:
                stderr.write('\n')
                stderr.flush()
    except FileNotFoundError:
        stderr.write('no keys found\n')
        return 1

    _write_file(sigset, sigset_path, stdout, append=append)
    return 0


def usage_softcred(out):
    out.write('Usage: %s softcred [-a] <softkey> <credset>\n' % (progname,))
    out.write('\n')
    out.write('  Generate a credential from a softkey.\n')
    out.write('\n')
    out.write('  Note: Softkeys do not support device attestations.\n')
    out.write('\n')
    out.write('Options:\n')
    out.write('  -a, --append\n')
    out.write('        append to set if it is already there, else create\n')
    out.write('  -r, --rp <rpid>\n')
    out.write('        set the relying party id\n')
    out.write('  -u, --user <userid>\n')
    out.write('        set the user id\n')


def cmd_softcred(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'ahr:u:', [
            'append',
            'help',
            'rp',
            'user',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_softcred(stderr)
        return 1

    append = False
    rp_id = None
    user_id = None
    errors = []
    for o, a in opts:
        if o in ('-h', '--help'):
            usage_softcred(stdout)
            return 0
        elif o in ('-a', '--append'):
            append = True
        elif o in ('-r', '--rp'):
            if rp_id is not None:
                errors.append('duplicate rp')
                continue
            rp_id = a
        elif o in ('-u', '--user'):
            if user_id is not None:
                errors.append('duplicate user')
                continue
            user_id = a
        else:
            assert False, 'invalid option'
    if errors or len(args) != 2:
        for error in errors:
            stderr.write('%s\n' % (error,))
        usage_softcred(stderr)
        return 1

    [softkey_path, credset_path] = args

    rp = _get_rp(rp_id)
    user = _get_user(user_id)

    softkey = _read_file(softkey_path, stdin)
    credset = _read_file(credset_path, stdin, append=True) if append else None

    credset = softcred(softkey, rp, user, credset=credset)

    _write_file(credset, credset_path, stdout, append=append)
    return 0


def usage_softkey(out):
    out.write('Usage: %s softkey <softkey>\n' % (progname,))
    out.write('\n')
    out.write('  Generate a softkey.\n')


def cmd_softkey(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'h', [
            'help',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_softkey(stderr)
        return 1

    for o, a in opts:
        if o in ('-h', '--help'):
            usage_softkey(stdout)
            return 0
        else:
            assert False, 'invalid option'
    if len(args) != 1:
        usage_softkey(stderr)
        return 1

    [softkey_path] = args

    softkey = softkeygen()

    _write_file(softkey, softkey_path, stdout)
    return 0


def usage_softsign(out):
    out.write('Usage: %s softsign [-a] <softkey> <credset> <msg> <sigset>\n' %
              (progname,))
    out.write('\n')
    out.write('  Sign the message in <msg> with any credentials in\n')
    out.write('  <credset> derived from <softkey> and store the\n')
    out.write('  resulting signatures in <sigset>.\n')
    out.write('\n')
    out.write('Options:\n')
    out.write('  -a, --append\n')
    out.write('        append to set if it is already there, else create\n')
    out.write('  -H, --header <header>\n')
    out.write('        use <header> as header instead of file name <msg>\n')
    out.write('  -r, --rp <rpid>\n')
    out.write('        set the relying party id\n')


def cmd_softsign(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'ahH:r:', [
            'append',
            'header',
            'help',
            'rp',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_softsign(stderr)
        return 1

    append = False
    header = None
    rp_id = None
    errors = []
    for o, a in opts:
        if o in ('-h', '--help'):
            usage_softsign(stdout)
            return 0
        elif o in ('-a', '--append'):
            append = True
        elif o in ('-H', '--header'):
            if header is not None:
                errors.append('duplicate header')
                continue
            header = a
        elif o in ('-r', '--rp'):
            if rp_id is not None:
                errors.append('duplicate rp')
                continue
            rp_id = a
        else:
            assert False, 'invalid option'
    if errors or len(args) != 4:
        for error in errors:
            stderr.write('%s\n' % (error,))
        usage_softsign(stderr)
        return 1

    [softkey_path, credset_path, msg_path, sigset_path] = args

    header = _get_header(header, msg_path, stderr)
    rp = _get_rp(rp_id)

    softkey = _read_file(softkey_path, stdin)
    credset = _read_file(credset_path, stdin)
    msg = _read_file(msg_path, stdin, maxbytes=64 * 1024 * 1024)
    sigset = _read_file(sigset_path, stdin, append=True) if append else None

    try:
        sigset = softsign(
            softkey, rp, credset, msg, header=header, sigset=sigset
        )
    except FileNotFoundError:
        stderr.write('no keys found\n')
        return 1

    _write_file(sigset, sigset_path, stdout, append=append)
    return 0


def usage_verify(out):
    out.write('Usage: %s verify <credset> <msg> <sigset>\n' % (progname,))
    out.write('\n')
    out.write('  Verify signatures on <msg>.  For every credential\n')
    out.write('  in <credset> with a valid signature on <msg> in\n')
    out.write('  <sigset>, print its base64url-encoded credential id,\n')
    out.write('  one per line.\n')
    out.write('\n')
    out.write('  Exits with status zero only if there is at least one\n')
    out.write('  valid signature from <credset> in <sigset>.\n')
    out.write('\n')
    out.write('Options:\n')
    out.write('  -H, --header <header>\n')
    out.write('        use <header> as header instead of file name <msg>\n')
    out.write('  -r, --rp <rpid>\n')
    out.write('        set the relying party id\n')


def cmd_verify(args, stdin, stdout, stderr):
    try:
        opts, args = getopt.getopt(args, 'hH:r:', [
            'header',
            'help',
            'rp',
        ])
    except getopt.GetoptError as e:
        stderr.write('%s\n' % (str(e),))
        usage_verify(stderr)
        return 1

    header = None
    rp_id = None
    errors = []
    for o, a in opts:
        if o in ('-h', '--help'):
            usage_verify(stdout)
            return 0
        elif o in ('-H', '--header'):
            if header is not None:
                errors.append('duplicate header')
                continue
            header = a
        elif o in ('-r', '--rp'):
            if rp_id is not None:
                errors.append('duplicate rp')
                continue
            rp_id = a
        else:
            assert False, 'invalid option'
    if errors or len(args) != 3:
        for error in errors:
            stderr.write('%s\n' % (error,))
        usage_verify(stderr)
        return 1

    [credset_path, msg_path, sigset_path] = args

    header = _get_header(header, msg_path, stderr)
    rp = _get_rp(rp_id)

    credset = _read_file(credset_path, stdin)
    msg = _read_file(msg_path, stdin, maxbytes=64 * 1024 * 1024)
    sigset = _read_file(sigset_path, stdin)
    verified = sorted(verify(rp, credset, msg, sigset, header=header))
    for credential_id in verified:
        extcredid = credid_externalize(credential_id)
        stdout.buffer.write(b'%s\n' % (extcredid,))
    return 0 if verified else 1


CMDS = {
    'attest': cmd_attest,
    'cred': cmd_cred,
    'dump': cmd_dump,
    'inlinesign': cmd_inlinesign,
    'inlineverify': cmd_inlineverify,
    'list': cmd_list,
    'merge': cmd_merge,
    'sign': cmd_sign,
    'softcred': cmd_softcred,
    'softkey': cmd_softkey,
    'softsign': cmd_softsign,
    'verify': cmd_verify,
}


def main():
    import sys
    return cmd(sys.argv, sys.stdin, sys.stdout, sys.stderr)


if __name__ == '__main__':
    import sys
    sys.exit(main())
