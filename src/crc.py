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


import zlib


# G = x^16 + x^14 + x^13 + x^12 + x^10 + x^8 + x^6 + x^4 + x^3 + x + 1,
#
# also known as 0xBAAD in Koopman notation.  Here, the least
# significant bit represents the highest-degree coefficient below 2^32,
# and CRC16_POLY represents x^16 mod G.  The polynomial was introduced
# in
#
#       Philip Koopman and Tridib Chakravarty, `Cyclic Redundancy Code
#       (CRC) Polynomial Selection For Embedded Networks',
#       International Conference on Dependable Systems and
#       Networks---DSN 2004.
#       http://users.ece.cmu.edu/~koopman/roses/dsn04/koopman04_crc_poly_embedded.pdf
#
# and guarantees Hamming distance at least 4 for data word lengths up
# to 2048 bits (i.e., guarantees detection of all <4-bit errors in data
# words of up to 2048 bits = 256 bytes).
#
CRC16_POLY = 0xDAAE


def crc16_8(crc, b):
    # If m_0 is the message so far as a polynomial over GF(2), and if
    # m_1 is the degree<8 polynomial over GF(2) represented by b, then
    # the CRC so far is
    #
    #   (m_0 x^32) mod G,
    #
    # and message after adding b is m_1 + m_0 x^8, so we want to
    # compute the CRC
    #
    #   [(m_1 + m_0 x^8) x^32] mod G.
    #
    # Note that m_1 x^{32 - 8} has degree <32, so it is unaffected by
    # reduction modulo G.  To add it, we xor b -- recall the lsb
    # represents the highest-degree coefficient.
    #
    crc ^= b                    # crc := (m_1 x^{32 - 8} + m_0 x^32) mod G

    # Multiply by x and reduce modulo G eight times:
    #
    #       crc := [x * (m_1 x^{32 - 8 + i} + m_0 x^{32 + i})] mod G
    #            = (m_1 x^{32 - 8 + i + 1} + m_0 x^{32 + i + 1}) mod G
    #
    for i in range(8):
        crc = (crc >> 1) ^ (CRC16_POLY & -(crc & 1))

    # Finally, we have:
    #
    #   crc = (m_1 x^32 + m_0 x^{32 + 8}) mod G
    #       = [(m_1 + m_0 x^8) x^32] mod G
    #
    return crc


# Precompute the update -- for each input byte, what we add to the CRC
# depends only on the sum of the highest eight coefficient positions
# with the byte added.
#
CRC16_8 = [crc16_8(0, b) for b in range(256)]


def crc16(s, crc=0):
    for b in bytearray(s):
        crc = (crc >> 8) ^ CRC16_8[(crc & 0xff) ^ b]
    return crc


# G := x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11
#       + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1,
#
# represented by 0xEDB88320 with highest-degree coefficient at lsb.
#
crc32 = zlib.crc32
