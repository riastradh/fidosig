Fidosig -- FIDO-based file signatures
=====================================

Taylor `Riastradh' Campbell <campbell+fidosig@mumble.net>

**Fidosig** is a signature scheme based on U2F/FIDO/webauthn.  You can
use it to sign files with a U2F security key, or optionally with
software using a secret stored on disk.  You can easily handle multiple
signers on a single document, and use `fidosig verify` in scripts to
implement verification policies such as thresholds.

- **WARNING: Fidosig is a draft work in progress.  All the data
  formats, command line interfaces, APIs, and the details of the
  signtaure scheme are subject to change during development until
  various details have been sorted out.**

Installation
------------

Standard Python package installation with setuptools.  Install in a
virtualenv so you don't screw anything up and aren't tempted to rely on
this while it's still under development.

```
virtualenv ~/fidosig-venv
. ~/fidosig-venv/bin/activate
pip install .
```

This depends on [python-fido2](https://github.com/Yubico/python-fido2).

Usage example
-------------

First, set the relying party and user name.  Setting the relying party
ensures that signatures for one application can't be fooled by those
for another.  The user name figures only into device attestation (to be
documented; see `fidosig attest`).

```
% export FIDOSIG_RP='{"id":"example.com","name":"Example LLC"}'
% export FIDOSIG_USER='{"id":"falken","name":"Falken","display_name":"Professor Falken"}'
```

Create a credential.  The credset.fsc file will be created to contain
your credential id, which is a unique identifier not linked to anything
else, and your public key, which is needed by anyone verifying
signatures.

```
% fidosig cred mycredset.fsc
tap key; waiting...
```

You can also add another credential if you have multiple U2F keys, such
as a primary one and a backup.  (It will let you know if you try to use
the same U2F key twice with the same relying party.)

```
% fidosig cred -a mycredset.fsc
tap key; waiting...
```

You can distribute credset.fsc to whoever you want to authenticate
future documents from you.

List the credential's id.  This id will appear in `fidosig verify`
output; you might save it into a script to implement signature
policies, such as ensuring that at least one member of two different
committees has signed a document, or at least three developers have
each signed with both a software key and a hardware key.

```
% fidosig list mycredset.fsc
WsL_USIIjO1uwG0PAPxNIfqcdJLcxZ1E8plHAwJWONqwKfKdrzm24Y-UQvwOdH_z3sElIf4aZcwOUIGHGtjg7ODF
-iduNhP5dUFohmugTg01bLc0DNpbjTwDAj0ld3_J1fazU9p9dq5C8E7zzlIJzmM-QBvrYOF_wHiQaIkDy_H0M8_i
```

Sign a message.

```
% echo hello world > foo.txt
% fidosig sign mycredset.fsc foo.txt foo.sig
tap key; waiting...
```

Verify the signature.  This command will print the credential ids of
all the signatories in the specified credential set.

```
% fidosig verify mycredset.fsc foo.txt foo.sig
WsL_USIIjO1uwG0PAPxNIfqcdJLcxZ1E8plHAwJWONqwKfKdrzm24Y-UQvwOdH_z3sElIf4aZcwOUIGHGtjg7ODF
```

Note that signature verification fails if the file name changes!

```
% mv foo.txt fooo.txt
% fidosig verify mycredset.fsc fooo.txt foo.sig
... Invalid signature.
```

But you can override it by passing a different header -- you can also
pass `-H <header>` to `fidosig sign` when creating the signature if you
want to use something other than the file name default.

```
% fidosig verify -H foo.txt mycredset.fsc fooo.txt foo.sig
WsL_USIIjO1uwG0PAPxNIfqcdJLcxZ1E8plHAwJWONqwKfKdrzm24Y-UQvwOdH_z3sElIf4aZcwOUIGHGtjg7ODF
% mv fooo.txt foo.txt
```

Add a new signature by tapping a different U2F device.  You can add
signatures by many different credentials.  (If you sign again with the
same U2F key, it will simply overwrite the existing signature.)

```
% fidosig sign -a mycredset.fsc foo.txt foo.sig
tap key; waiting...
```

You can also use software with a key stored in a file, without needing
a U2F key.  First, create a fidosig softkey and _keep the file secret_:

```
% fidosig softkey mysoftkey.fsk
```

Add a credential for this key to the set:

```
% fidosig softcred -a mysoftkey.fsk mycredset.fsc
```

Sign again, this time with the software key.

```
% fidosig softsign -a mysoftkey.fsk mycredset.fsc foo.txt foo.sig
```

Verify the signature once more:

```
% fidosig verify mycredset.fsc foo.txt foo.sig
WsL_USIIjO1uwG0PAPxNIfqcdJLcxZ1E8plHAwJWONqwKfKdrzm24Y-UQvwOdH_z3sElIf4aZcwOUIGHGtjg7ODF
hiLaGHLkqhisyTo9_19d9HYFvbBTtCzzC1-Z2jCtoU0K530X7G2OyEwaz_mWZsjINWeeOSUIeVmM0Eny
byIH2EiQ                                                                        -iduNhP5dUFohmugTg01bLc0DNpbjTwDAj0ld3_J1fazU9p9dq5C8E7zzlIJzmM-QBvrYOF_wHiQaIkDy_H0M8_i
```
