Fidosig -- FIDO-based digital signature tool (EXPERIMENTAL)
===========================================================

Taylor ‘Riastradh’ Campbell <campbell+fidosig@mumble.net>

**Fidosig** is a signature scheme based on U2F/FIDO/webauthn.  You can
use it to sign files with a U2F security key, or optionally with
software using a secret stored on disk.  You can easily handle multiple
signers on a single document, and use `fidosig verify` in scripts to
implement verification policies such as thresholds.

- **WARNING: Fidosig is an experimental draft work in progress.  All
  the data formats, command line interfaces, APIs, and the details of
  the signtaure scheme are subject to change during development until
  various details have been sorted out.**

Features
--------

- Just like login with U2F -- and unlike crypto smartcards -- fidosig
  doesn't require any tools to initialize, configure, examine, and
  manage key storage on your U2F device.  You just plug it in and tap
  when you want to create a public key or make a signature with it.

- Signatures and signed messages made by fidosig are _not_
  human-readable and have no human-readable components like comments.
  You should not be tempted to inspect them; you should only pass them
  through automated verification.

- Fidosig signs the file's name, not just the file's content.  You can
  specify an arbitrary header if you like instead of the file name, or
  an empty one -- but out of the box, an adversary can't, for example,
  just rename an old buggy software release to have a newer version
  number and still pass signature verification.

- Fidosig has reasonably simple compact data formats, based on CBOR of
  [RFC 7049](https://tools.ietf.org/html/rfc7049) like FIDO/webauthn,
  and a simple set of operations on the data formats -- it is meant to
  be easy to integrate into an existing application, either as a
  subprocess or via a Python API (XXX the API is not stable yet).

- Fidosig makes it easy to combine sets of credentials and sets of
  signatures together, and shows which signatories were verified on a
  file to facilitate writing verification policy scripts -- for
  example: must be signed by both the hardware token and the software
  token of each of at least three of ten authorized developers.

- Fidosig is boring crypto.  No fancy multiparty homomorphic robust
  multivariate-quadratic semisogenies in the neo-oracle model.

Installation
------------

Standard Python package installation with setuptools.  Install in a
virtualenv so you don't screw anything up and aren't tempted to rely on
this while it's still under development.

```shell
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

```shell
% export FIDOSIG_RP='{"id":"example.com","name":"Example LLC"}'
% export FIDOSIG_USER='{"id":"falken","name":"Falken","display_name":"Professor Falken"}'
```

Create a credential.  The credset.fsc file will be created to contain
your credential id, which is a unique identifier not linked to anything
else, and your public key, which is needed by anyone verifying
signatures.

```shell
% fidosig cred mycredset.fsc
tap key; waiting...
```

You can also add another credential if you have multiple U2F keys, such
as a primary one and a backup.  (It will let you know if you try to use
the same U2F key twice with the same relying party.)

```shell
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

```shell
% fidosig list mycredset.fsc
WsL_USIIjO1uwG0PAPxNIfqcdJLcxZ1E8plHAwJWONqwKfKdrzm24Y-UQvwOdH_z3sElIf4aZcwOUIGHGtjg7ODF
-iduNhP5dUFohmugTg01bLc0DNpbjTwDAj0ld3_J1fazU9p9dq5C8E7zzlIJzmM-QBvrYOF_wHiQaIkDy_H0M8_i
```

Sign a message.

```shell
% echo hello world > foo.txt
% fidosig sign mycredset.fsc foo.txt foo.sig
tap key; waiting...
```

Verify the signature.  This command will print the credential ids of
all the signatories in the specified credential set.

```shell
% fidosig verify mycredset.fsc foo.txt foo.sig
WsL_USIIjO1uwG0PAPxNIfqcdJLcxZ1E8plHAwJWONqwKfKdrzm24Y-UQvwOdH_z3sElIf4aZcwOUIGHGtjg7ODF
```

Note that signature verification fails if the file name changes!

```shell
% mv foo.txt fooo.txt
% fidosig verify mycredset.fsc fooo.txt foo.sig
... Invalid signature.
```

But you can override it by passing a different header -- you can also
pass `-H <header>` to `fidosig sign` when creating the signature if you
want to use something other than the file name default.

```shell
% fidosig verify -H foo.txt mycredset.fsc fooo.txt foo.sig
WsL_USIIjO1uwG0PAPxNIfqcdJLcxZ1E8plHAwJWONqwKfKdrzm24Y-UQvwOdH_z3sElIf4aZcwOUIGHGtjg7ODF
% mv fooo.txt foo.txt
```

Add a new signature by tapping a different U2F device.  You can add
signatures by many different credentials.  (If you sign again with the
same U2F key, it will simply overwrite the existing signature.)

```shell
% fidosig sign -a mycredset.fsc foo.txt foo.sig
tap key; waiting...
```

You can also use software with a key stored in a file, without needing
a U2F key.  First, create a fidosig softkey and _keep the file secret_:

```shell
% fidosig softkey mysoftkey.fsk
```

Add a credential for this key to the set:

```shell
% fidosig softcred -a mysoftkey.fsk mycredset.fsc
```

Sign again, this time with the software key.

```shell
% fidosig softsign -a mysoftkey.fsk mycredset.fsc foo.txt foo.sig
```

Verify the signature once more:

```shell
% fidosig verify mycredset.fsc foo.txt foo.sig
WsL_USIIjO1uwG0PAPxNIfqcdJLcxZ1E8plHAwJWONqwKfKdrzm24Y-UQvwOdH_z3sElIf4aZcwOUIGHGtjg7ODF
hiLaGHLkqhisyTo9_19d9HYFvbBTtCzzC1-Z2jCtoU0K530X7G2OyEwaz_mWZsjINWeeOSUIeVmM0EnybyIH2EiQ
-iduNhP5dUFohmugTg01bLc0DNpbjTwDAj0ld3_J1fazU9p9dq5C8E7zzlIJzmM-QBvrYOF_wHiQaIkDy_H0M8_i
```

Postscript
----------

fidosig basically does a Fido-Shamir transformation of U2F.
