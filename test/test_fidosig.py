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


import base64
import pytest

from fidosig._data import credid_internalize
from fidosig.attest import attest
from fidosig.list import listcreds
from fidosig.merge import merge
from fidosig.softcred import softcred
from fidosig.softkey import softkeygen
from fidosig.softsign import softsign
from fidosig.verify import verify


RP = {'id': 'example.com', 'name': 'Example LLC'}
USER = {'id': b'falken', 'name': 'Falken', 'display_name': 'Professor Falken'}
MSG = b'hello world\n'
HDR = b'msg'
NOTRANDOM24 = bytes(range(24))

CREDSET1 = base64.b64decode('''
RklET1NJR0OhWED6J242E/l1QWiGa6BODTVstzQM2luNPAMCPSV3f8nV9rNT2n12rkLwTvPOUgnO
Yz5AG+tg4X/AeJBoiQPL8fQzpQECAyYgASFYIDErESdCmkSI8RD4B5IKFgxewoLGoJSDhxqCdHZO
v555IlggDCcjc7ZP17Xu7eM9zMQwRexDcpgLiwDwW6aFFqTV1HUt+sHc
''')

CREDID1 = credid_internalize('''
-iduNhP5dUFohmugTg01bLc0DNpbjTwDAj0ld3_J1fazU9p9dq5C8E7zzlIJzmM-QBvrYOF_wHiQaIkDy_H0M8_i
''')

ATTSET1 = base64.b64decode('''
RklET1NJR0GhWED6J242E/l1QWiGa6BODTVstzQM2luNPAMCPSV3f8nV9rNT2n12rkLwTvPOUgnO
Yz5AG+tg4X/AeJBoiQPL8fQzWQPtowFmcGFja2VkAljEo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCr
E9ISVYbOGUdBAAAAAxSaICGO9kEzlriB+NW38fUAQPonbjYT+XVBaIZroE4NNWy3NAzaW408AwI9
JXd/ydX2s1PafXauQvBO885SCc5jPkAb62Dhf8B4kGiJA8vx9DOlAQIDJiABIVggMSsRJ0KaRIjx
EPgHkgoWDF7CgsaglIOHGoJ0dk6/nnkiWCAMJyNztk/Xte7t4z3MxDBF7ENymAuLAPBbpoUWpNXU
dQOjY2FsZyZjc2lnWEcwRQIgTrPho8IziSj/h/x+p5Fb7YsU8yIiLA1Ds85R2CZ2AEYCIQCGeWrH
dpBQtrSEEq3pAzxE8L/pbAA91W2WPbWkKxmpkmN4NWOBWQLBMIICvTCCAaWgAwIBAgIECwXNUzAN
BgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIw
MDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQ
BgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUG
A1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgMTg0OTI5NjE5MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEIRpvsbWJJcsKwRhffCrjqLSIEBR5sR7/9VXgfZdRvSsXaiUt7lns44WZIFuz6ii/j9f8
fadcBUJyrkhY5ZH8WqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYL
KwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQFJogIY72QTOWuIH41bfx9TAMBgNV
HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQA+/qPfPSrgclePfgTQ3VpLaNsBr+hjLhi04Lhz
QxiRGWwYS+vB1TOiPXeLsQQIwbmqQU51doVbCTaXGLNIr1zvbLAwhnLWH7i9m4ahCqaCzowtTvCQ
7VBUGP5T1M4eYnoo83IDCVjQj/pZG8QYgOGOigztGoWAf5CWcUF6C0UyFbONwUcqJEl2QLToa/7E
8VRjm4W46IAUljYkODVZASv8h3wLROx9p5TSBlSymtwdulxQe/DKbfNSvM3edA0up+EIJKLOOU+Q
TR2ZQV46fEW1/ih6m8vcaY6L3NW0eYpc7TXeijUJAgoUtya/vzmnRAecuY9bncoJt8PrvL2ir2kD
DJdWFQ==
''')

SIG1 = base64.b64decode('''
RklET1NJR1OhWED6J242E/l1QWiGa6BODTVstzQM2luNPAMCPSV3f8nV9rNT2n12rkLwTvPOUgnO
Yz5AG+tg4X/AeJBoiQPL8fQzowBYGNWk+iH4oOEjXSIaP1vlLr1NRs2WysZ6xwFYJaN5pvbur7ml
XjeMEYA04nUeaC+rny0wqxPSElWGzhlHAQAAAAwCWEgwRgIhALOaeEbmEhAVftaVomrzuy7acGeJ
f0hjgsvR0vedmfKzAiEA38pCpgXAy5OGqanLDnZyRMnyKV+d5w9AizDh1EOLAoGz8sRT
''')

CREDSET2 = base64.b64decode('''
RklET1NJR0OhWEBawv9RIgiM7W7AbQ8A/E0h+px0ktzFnUTymUcDAlY42rAp8p2vObbhj5RC/A50
f/PewSUh/hplzA5QgYca2ODspQECAyYgASFYIBUYSF8FOWP69o8zx3rG8T6oce3r6K54awqj2HiZ
RcV/IlggcB8eFXURTy/PRKq6dCKEznwmbLVPFBxisu/dKwOwkvpv8HiR
''')

CREDID2 = credid_internalize('''
WsL_USIIjO1uwG0PAPxNIfqcdJLcxZ1E8plHAwJWONqwKfKdrzm24Y-UQvwOdH_z3sElIf4aZcwOUIGHGtjg7ODF
''')

ATTSET2 = base64.b64decode('''
RklET1NJR0GhWEBawv9RIgiM7W7AbQ8A/E0h+px0ktzFnUTymUcDAlY42rAp8p2vObbhj5RC/A50
f/PewSUh/hplzA5QgYca2ODsWQPvowFmcGFja2VkAljEo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCr
E9ISVYbOGUdBAAAAAu6IKHlyHEkTl3U9/M6XByoAQFrC/1EiCIztbsBtDwD8TSH6nHSS3MWdRPKZ
RwMCVjjasCnyna85tuGPlEL8DnR/897BJSH+GmXMDlCBhxrY4OylAQIDJiABIVggFRhIXwU5Y/r2
jzPHesbxPqhx7evornhrCqPYeJlFxX8iWCBwHx4VdRFPL89Eqrp0IoTOfCZstU8UHGKy790rA7CS
+gOjY2FsZyZjc2lnWEgwRgIhAIy+SN5eSvKlUYWk/z4AN5bANhFyV97nJWlDoGHNtj4WAiEA6ulO
4YOIvNJYSTh7f3mVgu4sijW3rsnrW9JFXsX7HyljeDVjgVkCwjCCAr4wggGmoAMCAQICBFZmM30w
DQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcy
MDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG8xCzAJBgNVBAYTAlNFMRIw
EAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xKDAm
BgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE0NDk1Mzg0MjkwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAT/sayZX+lwzDJwPW0ZKPNi2oen84IgHGm8DTpl1bazdUv6SIxVbrvu0r2QktcMbnDV
UQAPHimn4HU+seUaKxIto2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzAT
BgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsrBgEEAYLlHAEBBAQSBBDuiCh5chxJE5d1PfzOlwcqMAwG
A1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAEQYt7eJNOrUqHRaTjaYRvOqV7XRsbNEyTLn
rkMVXndB36k+yNmN9kSUNs+lZuCIQEexWUp9IWGdHGUIb56vDxW8jWOnzPrdVgjK1yfEmQix+Gjj
GIM9CPOX5D6ZJWm4mLjTD9cO8IC0qEaMFH8LAuJlsDbBW3IVuHcT5/n9B/W54xvteleJuJq4hdsZ
yPy7q4HuSQhK22MFX71CwvPp6uaBR/JhbaShiQCvJjgibLki16iyk+fuohoxHCdRPOiScRFtb9ki
lDd6/QHFoxP0BPlKOZXRPMedmF7A17lxZjh7aLPIDfkABhS2d8e8djeZ9R/4nn4hAFuZFXmRXmU5
Q9tNhRPw
''')

SIG2 = base64.b64decode('''
RklET1NJR1OhWEBawv9RIgiM7W7AbQ8A/E0h+px0ktzFnUTymUcDAlY42rAp8p2vObbhj5RC/A50
f/PewSUh/hplzA5QgYca2ODsowBYGPPBvZMCDw0iOXSDk2dzwHx1g9/d5xUaSAFYJaN5pvbur7ml
XjeMEYA04nUeaC+rny0wqxPSElWGzhlHAQAAAAoCWEcwRQIhAKbRA+3rMBJTYTbv6QjoaqKa7Jmo
bddPedMZqJy7nCD6AiByedZgPBsCcJKR7rq28WpCgZaFxM5NIiSuFaFlUXBhx+dzDiw=
''')


def test_list_merge():
    assert listcreds(CREDSET1) == [CREDID1]
    assert listcreds(CREDSET2) == [CREDID2]
    assert listcreds(merge([CREDSET1, CREDSET2])) == sorted([CREDID1, CREDID2])
    assert listcreds(ATTSET1) == [CREDID1]
    assert listcreds(ATTSET2) == [CREDID2]
    assert listcreds(merge([ATTSET1, ATTSET2])) == sorted([CREDID1, CREDID2])


@pytest.mark.xfail(strict=True)
def test_list_rejects_sigset1():
    with pytest.raises(Exception):
        listcreds(SIG1)


@pytest.mark.xfail(strict=True)
def test_list_rejects_sigset2():
    with pytest.raises(Exception):
        listcreds(SIG2)


@pytest.mark.xfail(strict=True)
def test_list_rejects_sigset():
    with pytest.raises(Exception):
        listcreds(merge([SIG1, SIG2]))


def test_attest():
    attest(RP, USER, CREDSET1, ATTSET1)
    attest(RP, USER, CREDSET2, ATTSET2)
    attest(RP, USER, CREDSET1, merge([ATTSET1, ATTSET2]))
    attest(RP, USER, CREDSET2, merge([ATTSET1, ATTSET2]))
    # XXX refine exception
    with pytest.raises(Exception):
        attest(RP, USER, CREDSET1, ATTSET2)
    with pytest.raises(Exception):
        attest(RP, USER, CREDSET2, ATTSET1)
    with pytest.raises(Exception):
        attest(RP, USER, merge([CREDSET1, CREDSET2]), ATTSET1)
    with pytest.raises(Exception):
        attest(RP, USER, merge([CREDSET1, CREDSET2]), ATTSET2)


def test_verify():
    assert verify(RP, CREDSET1, MSG, SIG1, HDR) == set([CREDID1])
    assert verify(RP, CREDSET2, MSG, SIG2, HDR) == set([CREDID2])
    assert verify(RP, merge([CREDSET1, CREDSET2]), MSG, SIG1, HDR) == \
        set([CREDID1])
    assert verify(RP, merge([CREDSET1, CREDSET2]), MSG, SIG2, HDR) == \
        set([CREDID2])
    assert verify(RP, CREDSET1, MSG, merge([SIG1, SIG2]), HDR) == \
        set([CREDID1])
    assert verify(RP, CREDSET2, MSG, merge([SIG1, SIG2]), HDR) == \
        set([CREDID2])
    with pytest.raises(Exception):
        verify(RP, CREDSET1, MSG, SIG1)
    with pytest.raises(Exception):
        verify(RP, CREDSET2, MSG, SIG2)
    assert verify(RP, CREDSET1, MSG, SIG2, HDR) == set([])
    assert verify(RP, CREDSET2, MSG, SIG1, HDR) == set([])
    with pytest.raises(Exception):
        verify(RP, CREDSET1, MSG + b'\0', SIG1, HDR)
    with pytest.raises(Exception):
        verify(RP, CREDSET2, MSG + b'\0', SIG2, HDR)


def test_softkey():
    softkey = softkeygen()
    credset = softcred(softkey, RP, USER)
    ids = listcreds(credset)
    sigset = softsign(softkey, RP, credset, MSG, randomization=NOTRANDOM24)
    assert ids == sorted(verify(RP, credset, MSG, sigset))
    sigset_ = softsign(softkey, RP, credset, MSG, randomization=NOTRANDOM24)
    assert sigset == sigset_
