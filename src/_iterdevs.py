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


import threading

from fido2.client import ClientError
from fido2.hid import CtapHidDevice


def iterdevs(per_device):
    lock = threading.Lock()
    cancel_ev = threading.Event()
    result = [None]
    ok = [False]

    def go(dev):
        try:
            r = per_device(dev, cancel_ev)
        except ClientError as e:
            if e.code != ClientError.ERR.TIMEOUT:
                raise
        with lock:
            if not ok[0]:
                result[0] = r
                ok[0] = True
                cancel_ev.set()

    threads = []
    for dev in CtapHidDevice.list_devices():
        t = threading.Thread(target=go, args=(dev,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    if not ok[0]:
        raise FileNotFoundError
    return result[0]
