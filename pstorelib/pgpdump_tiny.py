# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore-lib -- Python Protected Password Store (Library)
Copyright (C) 2013,2015,2017,2018  Walter Doekes <wdoekes>, OSSO B.V.

    This library is free software; you can redistribute it and/or modify it
    under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or (at
    your option) any later version.

    This library is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307,
    USA.

The code herein is mostly taken from python-pgpdump by DanMcGee, which in turn
is derived from 'pgpdump' by Kazuhiko Yamamoto.

https://pypi.python.org/pypi/pgpdump/1.3
http://www.mew.org/~kazu/proj/pgpdump/

It is trimmed down to only return the PGP key id.
"""
import hashlib
from base64 import b64decode
from struct import unpack


__all__ = ('AsciiData', 'BinaryData')


def get_int(data, offset, size):
    letter = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}[size]
    binary = data[offset:(offset + size)]
    try:
        integer = unpack('>%s' % (letter,), binary)[0]
    except Exception:
        raise Exception('unpack failed on %r' % (binary,))
    return integer


def my_ord(byte):
    if not isinstance(byte, int):
        byte = ord(byte)
    return byte


def get_mpi(data, offset):
    """
    Gets a multi-precision integer as per RFC-4880.
    Returns the MPI and the new offset.
    See: http://tools.ietf.org/html/rfc4880#section-3.2
    """
    # #return None, int((get_int(data, offset, 2) + 7) / 8) + 2
    mpi_len = get_int(data, offset, 2)
    offset += 2
    to_process = (mpi_len + 7) // 8
    mpi = 0
    i = -4
    for i in range(0, to_process - 3, 4):
        mpi <<= 32
        mpi += get_int(data, offset + i, 4)
    for j in range(i + 4, to_process):
        mpi <<= 8
        mpi += my_ord(data[offset + j])
    # Python 3.2 and later alternative:
    # #mpi = int.from_bytes(data[offset:offset + to_process], byteorder='big')
    offset += to_process
    return mpi, offset


class BinaryData(object):
    """
    The base object used for extracting PGP data packets. This expects fully
    binary data as input; such as that read from a .sig or .gpg file.
    """
    binary_tag_flag = 0x80

    def __init__(self, data):
        if not data:
            raise Exception("no data to parse")
        if len(data) <= 1:
            raise Exception("data too short")

        # 7th bit of the first byte must be a 1
        if not bool(my_ord(data[0]) & self.binary_tag_flag):
            raise Exception("incorrect binary data")
        self.data = data
        self.length = len(data)

    def packets(self):
        packet = self.get_public_key()
        if packet:
            yield packet

    def get_public_key(self):
        """
        Return the public key packet.
        A generator function returning PGP data packets.
        """
        offset = 0
        while offset < self.length:
            tag = my_ord(self.data[offset]) & 0x3f
            new = bool(my_ord(self.data[offset]) & 0x40)
            if new:
                pos = offset + 1
                data_offset, length, partial = new_tag_length(self.data, pos)
                data_offset += 1
            else:
                tag >>= 2
                data_offset, length = old_tag_length(self.data, offset)
            data_offset += 1
            offset += data_offset

            if tag == 6:
                end = offset + length
                packet_data = self.data[offset:end]
                packet = PublicKeyPacket(tag, new, packet_data)
                return packet

            offset += length
        return None


class AsciiData(BinaryData):
    def __init__(self, data):
        lines = [i.strip() for i in data.strip().split('\n')]

        if not lines[0].startswith('----'):  # -----BEGIN PGP PUBLIC KEY BLOCK
            raise ValueError('missing BEGIN PGP PUBLIC KEY BLOCK')
        lines.pop(0)

        if not lines[-1].startswith('----'):  # -----END PGP PUBLIC KEY BLOCK
            raise ValueError('missing END PGP PUBLIC KEY BLOCK')
        lines.pop()

        # Drop optional checksum that starts with '='.
        if lines[-1].startswith('='):
            lines.pop()

        # Drop optional headers before the actual data.
        # E.g. "Version: GnuPG v1.4.11 (GNU/Linux)"
        if '' in lines:
            while lines[0] != '':
                lines.pop(0)
            lines.pop(0)
        # Should be only once.
        if '' in lines:
            raise ValueError('excess LF in public key block?')

        data = ''.join(i.strip() for i in lines)
        decoded = b64decode(data)
        super(AsciiData, self).__init__(decoded)


class PublicKeyPacket(object):
    def __init__(self, raw, new, data):
        self.raw = raw
        self.new = new
        self.length = len(data)
        self.data = data

        self.pubkey_version = None
        self.key_id = None
        self.raw_pub_algorithm = None
        self.pub_algorithm_type = None
        self.modulus = None
        self.exponent = None
        self.prime = None

        self.parse()

    def parse(self):
        self.pubkey_version = my_ord(self.data[0])
        offset = 1
        if self.pubkey_version in (2, 3):
            offset += 4  # raw_creation_time
            offset += 2  # days_valid

            self.raw_pub_algorithm = my_ord(self.data[offset])
            offset += 1
            offset = self.parse_key_material(offset)

            # #md5 = hashlib.md5()
            # Key type must be RSA for v2 and v3 public keys
            if self.pub_algorithm_type == "rsa":
                key_id = ('%X' % self.modulus)[-8:].zfill(8)
                self.key_id = key_id.encode('ascii')
                # #md5.update(get_int_bytes(self.modulus))
                # #md5.update(get_int_bytes(self.exponent))
            elif self.pub_algorithm_type == "elg":
                # Of course, there are ELG keys in the wild too. This formula
                # for calculating key_id and fingerprint is derived from an old
                # key and there is a test case based on it.
                key_id = ('%X' % self.prime)[-8:].zfill(8)
                self.key_id = key_id.encode('ascii')
                # #md5.update(get_int_bytes(self.prime))
                # #md5.update(get_int_bytes(self.group_gen))
            else:
                raise Exception(
                    "Invalid non-RSA v%d public key" % self.pubkey_version)
            # #self.fingerprint = md5.hexdigest().upper().encode('ascii')
        elif self.pubkey_version == 4:
            sha1 = hashlib.sha1()
            sha1.update(b'%c%c%c' % (
                0x99, (self.length >> 8) & 0xff, self.length & 0xff))
            sha1.update(self.data)
            fingerprint = sha1.hexdigest().upper().encode('ascii')
            self.key_id = fingerprint[24:]

            offset += 4  # raw_creation_time
            self.raw_pub_algorithm = my_ord(self.data[offset])
            offset += 1

            offset = self.parse_key_material(offset)
        else:
            raise Exception(
                "Unsupported public key packet, version %d" %
                self.pubkey_version)

        return offset

    def parse_key_material(self, offset):
        if self.raw_pub_algorithm in (1, 2, 3):
            self.pub_algorithm_type = "rsa"
            # n, e
            self.modulus, offset = get_mpi(self.data, offset)
            self.exponent, offset = get_mpi(self.data, offset)
        elif self.raw_pub_algorithm == 17:
            self.pub_algorithm_type = "dsa"
            # p, q, g, y
            self.prime, offset = get_mpi(self.data, offset)
            self.group_order, offset = get_mpi(self.data, offset)
            self.group_gen, offset = get_mpi(self.data, offset)
            self.key_value, offset = get_mpi(self.data, offset)
        elif self.raw_pub_algorithm in (16, 20):
            self.pub_algorithm_type = "elg"
            # p, g, y
            self.prime, offset = get_mpi(self.data, offset)
            self.group_gen, offset = get_mpi(self.data, offset)
            self.key_value, offset = get_mpi(self.data, offset)
        elif 100 <= self.raw_pub_algorithm <= 110:
            # Private/Experimental algorithms, just move on
            pass
        else:
            raise Exception(
                "Unsupported public key algorithm %d" % self.raw_pub_algorithm)

        return offset


def new_tag_length(data, start):
    """
    Takes a bytearray of data as input, as well as an offset of where to
    look. Returns a derived (offset, length, partial) tuple.
    """
    first = my_ord(data[start])
    offset = length = 0
    partial = False

    if first < 192:
        length = first
    elif first < 224:
        offset = 1
        length = ((first - 192) << 8) + my_ord(data[start + 1]) + 192
    elif first == 255:
        offset = 4
        length = get_int(data, start + 1, 4)
    else:
        # partial length, 224 <= l < 255
        length = 1 << (first & 0x1f)
        partial = True

    return (offset, length, partial)


def old_tag_length(data, start):
    """
    Takes a bytearray of data as input, as well as an offset of where to
    look. Returns a derived (offset, length) tuple.
    """
    offset = length = 0
    temp_len = my_ord(data[start]) & 0x03

    if temp_len in (0, 1, 2):
        size = (1, 2, 4)[temp_len]
        offset = size
        length = get_int(data, start + 1, size)
    elif temp_len == 3:
        length = len(data) - start - 1

    return (offset, length)
