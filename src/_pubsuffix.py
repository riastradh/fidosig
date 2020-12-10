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


from pkg_resources import resource_filename


def _read_public_suffix_list(path):
    with open(path, 'rb') as f:
        all_lines = f.readlines()
        lines = (line for line in all_lines if not line.startswith(b'//'))
        return set(line.decode('utf8').strip() for line in lines)


public_suffixes_path = \
    resource_filename(__name__, 'data/public_suffix_list.dat')
public_suffixes = _read_public_suffix_list(public_suffixes_path)
