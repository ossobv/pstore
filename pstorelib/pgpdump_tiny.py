# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore-lib -- Python Protected Password Store (Library)
Copyright (C) 2013,2015,2017,2018,2024  Walter Doekes <wdoekes>, OSSO B.V.

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

The code herein is mostly taken from python-pgpdump by Fuyukai, derived from
python-pgpdump by DanMcGee, which in turn is derived from 'pgpdump' by Kazuhiko
Yamamoto.

https://pypi.org/project/pgpdump3/1.5.2 (https://github.com/SkierPGP)
https://pypi.python.org/pypi/pgpdump/1.3
http://www.mew.org/~kazu/proj/pgpdump/

It is trimmed down to only return the PGP PublicKeyPacket packets, from which
we need the PGP key id.
(Also improved performance of some int/binary functions.)
"""
import hashlib
from base64 import b64decode
from datetime import datetime, timedelta
from math import ceil, log


__all__ = ('AsciiData', 'BinaryData')


class PgpdumpException(ValueError):
    """
    Base exception class raised by any parsing errors, etc.
    """
    pass


# 256 values corresponding to each possible byte
CRC24_TABLE = (
    0x000000, 0x864cfb, 0x8ad50d, 0x0c99f6, 0x93e6e1, 0x15aa1a, 0x1933ec,
    0x9f7f17, 0xa18139, 0x27cdc2, 0x2b5434, 0xad18cf, 0x3267d8, 0xb42b23,
    0xb8b2d5, 0x3efe2e, 0xc54e89, 0x430272, 0x4f9b84, 0xc9d77f, 0x56a868,
    0xd0e493, 0xdc7d65, 0x5a319e, 0x64cfb0, 0xe2834b, 0xee1abd, 0x685646,
    0xf72951, 0x7165aa, 0x7dfc5c, 0xfbb0a7, 0x0cd1e9, 0x8a9d12, 0x8604e4,
    0x00481f, 0x9f3708, 0x197bf3, 0x15e205, 0x93aefe, 0xad50d0, 0x2b1c2b,
    0x2785dd, 0xa1c926, 0x3eb631, 0xb8faca, 0xb4633c, 0x322fc7, 0xc99f60,
    0x4fd39b, 0x434a6d, 0xc50696, 0x5a7981, 0xdc357a, 0xd0ac8c, 0x56e077,
    0x681e59, 0xee52a2, 0xe2cb54, 0x6487af, 0xfbf8b8, 0x7db443, 0x712db5,
    0xf7614e, 0x19a3d2, 0x9fef29, 0x9376df, 0x153a24, 0x8a4533, 0x0c09c8,
    0x00903e, 0x86dcc5, 0xb822eb, 0x3e6e10, 0x32f7e6, 0xb4bb1d, 0x2bc40a,
    0xad88f1, 0xa11107, 0x275dfc, 0xdced5b, 0x5aa1a0, 0x563856, 0xd074ad,
    0x4f0bba, 0xc94741, 0xc5deb7, 0x43924c, 0x7d6c62, 0xfb2099, 0xf7b96f,
    0x71f594, 0xee8a83, 0x68c678, 0x645f8e, 0xe21375, 0x15723b, 0x933ec0,
    0x9fa736, 0x19ebcd, 0x8694da, 0x00d821, 0x0c41d7, 0x8a0d2c, 0xb4f302,
    0x32bff9, 0x3e260f, 0xb86af4, 0x2715e3, 0xa15918, 0xadc0ee, 0x2b8c15,
    0xd03cb2, 0x567049, 0x5ae9bf, 0xdca544, 0x43da53, 0xc596a8, 0xc90f5e,
    0x4f43a5, 0x71bd8b, 0xf7f170, 0xfb6886, 0x7d247d, 0xe25b6a, 0x641791,
    0x688e67, 0xeec29c, 0x3347a4, 0xb50b5f, 0xb992a9, 0x3fde52, 0xa0a145,
    0x26edbe, 0x2a7448, 0xac38b3, 0x92c69d, 0x148a66, 0x181390, 0x9e5f6b,
    0x01207c, 0x876c87, 0x8bf571, 0x0db98a, 0xf6092d, 0x7045d6, 0x7cdc20,
    0xfa90db, 0x65efcc, 0xe3a337, 0xef3ac1, 0x69763a, 0x578814, 0xd1c4ef,
    0xdd5d19, 0x5b11e2, 0xc46ef5, 0x42220e, 0x4ebbf8, 0xc8f703, 0x3f964d,
    0xb9dab6, 0xb54340, 0x330fbb, 0xac70ac, 0x2a3c57, 0x26a5a1, 0xa0e95a,
    0x9e1774, 0x185b8f, 0x14c279, 0x928e82, 0x0df195, 0x8bbd6e, 0x872498,
    0x016863, 0xfad8c4, 0x7c943f, 0x700dc9, 0xf64132, 0x693e25, 0xef72de,
    0xe3eb28, 0x65a7d3, 0x5b59fd, 0xdd1506, 0xd18cf0, 0x57c00b, 0xc8bf1c,
    0x4ef3e7, 0x426a11, 0xc426ea, 0x2ae476, 0xaca88d, 0xa0317b, 0x267d80,
    0xb90297, 0x3f4e6c, 0x33d79a, 0xb59b61, 0x8b654f, 0x0d29b4, 0x01b042,
    0x87fcb9, 0x1883ae, 0x9ecf55, 0x9256a3, 0x141a58, 0xefaaff, 0x69e604,
    0x657ff2, 0xe33309, 0x7c4c1e, 0xfa00e5, 0xf69913, 0x70d5e8, 0x4e2bc6,
    0xc8673d, 0xc4fecb, 0x42b230, 0xddcd27, 0x5b81dc, 0x57182a, 0xd154d1,
    0x26359f, 0xa07964, 0xace092, 0x2aac69, 0xb5d37e, 0x339f85, 0x3f0673,
    0xb94a88, 0x87b4a6, 0x01f85d, 0x0d61ab, 0x8b2d50, 0x145247, 0x921ebc,
    0x9e874a, 0x18cbb1, 0xe37b16, 0x6537ed, 0x69ae1b, 0xefe2e0, 0x709df7,
    0xf6d10c, 0xfa48fa, 0x7c0401, 0x42fa2f, 0xc4b6d4, 0xc82f22, 0x4e63d9,
    0xd11cce, 0x575035, 0x5bc9c3, 0xdd8538
)


def crc24(data):
    """
    Implementation of the CRC-24 algorithm used by OpenPGP.
    """
    # CRC-24-Radix-64
    # x24 + x23 + x18 + x17 + x14 + x11 + x10 + x7 + x6
    #   + x5 + x4 + x3 + x + 1 (OpenPGP)
    # 0x864CFB / 0xDF3261 / 0xC3267D
    crc = 0x00b704ce
    # this saves a bunch of slower global accesses
    crc_table = CRC24_TABLE
    for byte in data:
        tbl_idx = ((crc >> 16) ^ byte) & 0xff
        crc = (crc_table[tbl_idx] ^ (crc << 8)) & 0x00ffffff
    return crc


def get_hex_data(data, offset, byte_count):
    """
    Pull the given number of bytes from data at offset and return as a
    hex-encoded string.

    Original (1% slower) version:

        key_data = data[offset:offset + byte_count]
        key_id = binascii.hexlify(key_data)
        return key_id.upper()
    """
    key_data = data[offset:offset + byte_count]
    return key_data.hex().encode().upper()


def get_key_id(data, offset):
    """
    Pull eight bytes from data at offset and return as a 16-byte hex-encoded
    string.
    """
    return get_hex_data(data, offset, 8)


def get_int2(data, offset):
    """
    Pull two bytes from data at offset and return as an integer.
    """
    return (data[offset] << 8) + data[offset + 1]


def get_int4(data, offset):
    """
    Pull four bytes from data at offset and return as an integer.
    """
    return ((data[offset] << 24) + (data[offset + 1] << 16)
            + (data[offset + 2] << 8) + data[offset + 3])


def get_int_bytes(data):
    """
    Get the big-endian byte form of an integer or MPI.

    Original (2x slower) version:

        hexval = '%X' % data
        new_len = (len(hexval) + 1) // 2 * 2
        hexval = hexval.zfill(new_len)
        return binascii.unhexlify(hexval.encode('ascii'))
    """
    byte_length = (data.bit_length() + 7) // 8 or 1  # calc byte len
    return data.to_bytes(byte_length, 'big')


def get_mpi(data, offset):
    """
    Gets a multi-precision integer as per RFC-4880.
    Returns the MPI and the new offset.
    See: http://tools.ietf.org/html/rfc4880#section-3.2

    Original (30% slower) version:

        ...
        mpi = 0
        i = -4
        for i in range(0, to_process - 3, 4):
            mpi <<= 32
            mpi += get_int4(data, offset + i)
        for j in range(i + 4, to_process):
            mpi <<= 8
            mpi += data[offset + j]
        ...
    """
    mpi_len = get_int2(data, offset)
    offset += 2
    to_process = (mpi_len + 7) // 8
    mpi = int.from_bytes(data[offset:offset + to_process], byteorder='big')
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
            raise PgpdumpException("no data to parse")
        if len(data) <= 1:
            raise PgpdumpException("data too short")

        data = bytearray(data)

        # 7th bit of the first byte must be a 1
        if not bool(data[0] & self.binary_tag_flag):
            raise PgpdumpException("incorrect binary data")
        self.data = data
        self.length = len(data)

    def packets(self):
        """
        A generator function returning PGP data packets.
        """
        offset = 0
        while offset < self.length:
            total_length, packet = construct_packet(self.data, offset)
            offset += total_length
            yield packet

    def __repr__(self):
        return "<%s: length %d>" % (
                self.__class__.__name__, self.length)


class AsciiData(BinaryData):
    """
    A wrapper class that supports ASCII-armored input. It searches for the
    first PGP magic header and extracts the data contained within.
    """
    def __init__(self, data):
        self.original_data = data
        if not isinstance(data, bytes):
            data = data.encode()
        data = self.strip_magic(data)
        data, known_crc = self.split_data_crc(data)
        data = bytearray(b64decode(data))
        if known_crc:
            # verify it if we could find it
            actual_crc = crc24(data)
            if known_crc != actual_crc:
                raise PgpdumpException(
                    "CRC failure: known 0x%x, actual 0x%x" % (
                        known_crc, actual_crc))
        super(AsciiData, self).__init__(data)

    @staticmethod
    def strip_magic(data):
        """
        Strip away the '-----BEGIN PGP SIGNATURE-----' and related cruft so
        we can safely base64 decode the remainder.
        """
        idx = 0
        magic = b'-----BEGIN PGP '
        ignore = b'-----BEGIN PGP SIGNED '

        # find our magic string, skiping our ignored string
        while True:
            idx = data.find(magic, idx)
            if data[idx:len(ignore)] != ignore:
                break
            idx += 1

        if idx >= 0:
            # find the start of the actual data. it always immediately follows
            # a blank line, meaning headers are done.
            nl_idx = data.find(b'\n\n', idx)
            if nl_idx < 0:
                nl_idx = data.find(b'\r\n\r\n', idx)
            if nl_idx < 0:
                raise PgpdumpException(
                        "found magic, could not find start of data")
            # now find the end of the data.
            end_idx = data.find(b'-----', nl_idx)
            if end_idx:
                data = data[nl_idx:end_idx]
            else:
                data = data[nl_idx:]
        return data

    @staticmethod
    def split_data_crc(data):
        """
        The Radix-64 format appends any CRC checksum to the end of the data
        block, in the form '=alph', where there are always 4 ASCII characters
        corresponding to 3 digits (24 bits). Look for this special case.
        """
        # don't let newlines trip us up
        data = data.rstrip()
        # this funkyness makes it work without changes in Py2 and Py3
        if data[-5] in (b'=', ord(b'=')):
            # CRC is returned without the = and converted to a decimal
            crc = b64decode(data[-4:])
            # same noted funkyness as above, due to bytearray implementation
            crc = [ord(c) if isinstance(c, str) else c for c in crc]
            crc = (crc[0] << 16) + (crc[1] << 8) + crc[2]
            return (data[:-5], crc)
        return (data, None)


class Packet(object):
    """
    The base packet object containing various fields pulled from the packet
    header as well as a slice of the packet data.
    """

    def __init__(self, raw, name, new, data, original_data):
        self.raw = raw
        self.name = name
        self.new = new
        self.length = len(data)
        self.data = data
        self.original_data = original_data

        # now let subclasses work their magic
        self.parse()

    def parse(self):
        """
        Perform any parsing necessary to populate fields on this packet.
        This method is called as the last step in __init__(). The base class
        method is a no-op; subclasses should use this as required.
        """
        return 0

    def __repr__(self):
        new = "old"
        if self.new:
            new = "new"
        return "<%s: %s (%d), %s, length %d>" % (
            self.__class__.__name__, self.name, self.raw, new, self.length)


class AlgoLookup(object):
    """
    Mixin class containing algorithm lookup methods.
    """
    pub_algorithms = {
        1: "RSA Encrypt or Sign",
        2: "RSA Encrypt-Only",
        3: "RSA Sign-Only",
        16: "ElGamal Encrypt-Only",
        17: "DSA Digital Signature Algorithm",
        18: "Elliptic Curve",
        19: "ECDSA",
        20: "Formerly ElGamal Encrypt or Sign",
        21: "Diffie-Hellman",
    }

    # OID stuff? Not sure if it should be here, but why not?
    # TODO: Add more OIDS.
    oids = {
        b'2B81040023': ("NIST P-521", 521),
        b'2B81040022': ("NIST P-384", 384),
        b'2A8648CE3D030107': ("NIST P-256", 256),
        b'2B240303020801010D': ("Brainpool P512 r1", 512),
        b'2B240303020801010B': ("Brainpool P384 r1", 384),
        b'2B2403030208010107': ("Brainpool P256 r1", 256),
        b'2B06010401DA470F01': ("Curve 25519", None)
    }

    @classmethod
    def lookup_pub_algorithm(cls, alg):
        if 100 <= alg <= 110:
            return "Private/Experimental algorithm"
        return cls.pub_algorithms.get(alg, "Unknown")

    @classmethod
    def lookup_oid(cls, oid):
        return cls.oids.get(oid, ("Unknown", None))

    hash_algorithms = {
        1: "MD5",
        2: "SHA1",
        3: "RIPEMD160",
        8: "SHA256",
        9: "SHA384",
        10: "SHA512",
        11: "SHA224",
    }

    @classmethod
    def lookup_hash_algorithm(cls, alg):
        # reserved values check
        if alg in (4, 5, 6, 7):
            return "Reserved"
        if 100 <= alg <= 110:
            return "Private/Experimental algorithm"
        return cls.hash_algorithms.get(alg, "Unknown")

    sym_algorithms = {
        # (Name, IV length)
        0: ("Plaintext or unencrypted", 0),
        1: ("IDEA", 8),
        2: ("Triple-DES", 8),
        3: ("CAST5", 8),
        4: ("Blowfish", 8),
        5: ("Reserved", 8),
        6: ("Reserved", 8),
        7: ("AES with 128-bit key", 16),
        8: ("AES with 192-bit key", 16),
        9: ("AES with 256-bit key", 16),
        10: ("Twofish with 256-bit key", 16),
        11: ("Camellia with 128-bit key", 16),
        12: ("Camellia with 192-bit key", 16),
        13: ("Camellia with 256-bit key", 16),
    }

    @classmethod
    def _lookup_sym_algorithm(cls, alg):
        return cls.sym_algorithms.get(alg, ("Unknown", 0))

    @classmethod
    def lookup_sym_algorithm(cls, alg):
        return cls._lookup_sym_algorithm(alg)[0]

    @classmethod
    def lookup_sym_algorithm_iv(cls, alg):
        return cls._lookup_sym_algorithm(alg)[1]


class SignatureSubpacket(object):
    """
    A signature subpacket containing a type, type name, some flags, and the
    contained data.
    """
    CRITICAL_BIT = 0x80
    CRITICAL_MASK = 0x7f

    def __init__(self, raw, hashed, data):
        self.raw = raw
        self.subtype = raw & self.CRITICAL_MASK
        self.hashed = hashed
        self.critical = bool(raw & self.CRITICAL_BIT)
        self.length = len(data)
        self.data = data

    subpacket_types = {
        2: "Signature Creation Time",
        3: "Signature Expiration Time",
        4: "Exportable Certification",
        5: "Trust Signature",
        6: "Regular Expression",
        7: "Revocable",
        9: "Key Expiration Time",
        10: "Placeholder for backward compatibility",
        11: "Preferred Symmetric Algorithms",
        12: "Revocation Key",
        16: "Issuer",
        20: "Notation Data",
        21: "Preferred Hash Algorithms",
        22: "Preferred Compression Algorithms",
        23: "Key Server Preferences",
        24: "Preferred Key Server",
        25: "Primary User ID",
        26: "Policy URI",
        27: "Key Flags",
        28: "Signer's User ID",
        29: "Reason for Revocation",
        30: "Features",
        31: "Signature Target",
        32: "Embedded Signature",
    }

    @property
    def name(self):
        if self.subtype in (0, 1, 8, 13, 14, 15, 17, 18, 19):
            return "Reserved"
        return self.subpacket_types.get(self.subtype, "Unknown")

    def __repr__(self):
        extra = ""
        if self.hashed:
            extra += "hashed, "
        if self.critical:
            extra += "critical, "
        return "<%s: %s, %slength %d>" % (
            self.__class__.__name__, self.name, extra, self.length)


class SignaturePacket(Packet, AlgoLookup):
    def __init__(self, *args, **kwargs):
        self.sig_version = None
        self.raw_sig_type = None
        self.raw_pub_algorithm = None
        self.raw_hash_algorithm = None
        self.raw_creation_time = None
        self.creation_time = None
        self.raw_expiration_time = None
        self.expiration_time = None
        self.raw_key_expiration_time = None
        self.key_id = None
        self.hash2 = None
        self.subpackets = []

        self.sig_data = None

        super(SignaturePacket, self).__init__(*args, **kwargs)

    def parse(self):
        self.sig_version = self.data[0]
        offset = 1
        if self.sig_version in (2, 3):
            # 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
            # |  |  [  ctime  ] [ key_id                 ] |
            # |  |-type                           pub_algo-|
            # |-hash material
            # 10 11 12
            # |  [hash2]
            # |-hash_algo

            # "hash material" byte must be 0x05
            if self.data[offset] != 0x05:
                raise PgpdumpException("Invalid v3 signature packet")
            offset += 1

            self.raw_sig_type = self.data[offset]
            offset += 1

            self.raw_creation_time = get_int4(self.data, offset)
            self.creation_time = datetime.utcfromtimestamp(
                self.raw_creation_time)
            offset += 4

            self.key_id = get_key_id(self.data, offset)
            offset += 8

            self.raw_pub_algorithm = self.data[offset]
            offset += 1

            self.raw_hash_algorithm = self.data[offset]
            offset += 1

            self.hash2 = self.data[offset:offset + 2]
            offset += 2

        elif self.sig_version == 4:
            # 00 01 02 03 ... <hashedsubpackets..> <subpackets..> [hash2]
            # |  |  |-hash_algo
            # |  |-pub_algo
            # |-type

            self.raw_sig_type = self.data[offset]
            offset += 1

            self.raw_pub_algorithm = self.data[offset]
            offset += 1

            self.raw_hash_algorithm = self.data[offset]
            offset += 1

            # next is hashed subpackets
            length = get_int2(self.data, offset)
            offset += 2
            self.parse_subpackets(offset, length, True)
            offset += length

            # followed by subpackets
            length = get_int2(self.data, offset)
            offset += 2
            self.parse_subpackets(offset, length, False)
            offset += length

            self.hash2 = self.data[offset:offset + 2]
            offset += 2

            self.sig_data, offset = get_mpi(self.data, offset)
        else:
            raise PgpdumpException("Unsupported signature packet, version %d" %
                                   self.sig_version)

        return offset

    def parse_subpackets(self, outer_offset, outer_length, hashed=False):
        offset = outer_offset
        while offset < outer_offset + outer_length:
            # each subpacket is [variable length] [subtype] [data]
            sub_offset, sub_len, sub_part = new_tag_length(self.data, offset)
            # sub_len includes the subtype single byte, knock that off
            sub_len -= 1
            # initial length bytes
            offset += sub_offset

            subtype = self.data[offset]
            offset += 1

            sub_data = self.data[offset:offset + sub_len]
            if len(sub_data) != sub_len:
                raise PgpdumpException(
                    "Unexpected subpackets length: expected %d, got %d" % (
                        sub_len, len(sub_data)))
            subpacket = SignatureSubpacket(subtype, hashed, sub_data)
            if subpacket.subtype == 2:
                self.raw_creation_time = get_int4(subpacket.data, 0)
                self.creation_time = datetime.utcfromtimestamp(
                    self.raw_creation_time)
            elif subpacket.subtype == 3:
                self.raw_expiration_time = get_int4(subpacket.data, 0)
            elif subpacket.subtype == 9:
                self.raw_key_expiration_time = get_int4(subpacket.data, 0)
            elif subpacket.subtype == 16:
                self.key_id = get_key_id(subpacket.data, 0)
            offset += sub_len
            self.subpackets.append(subpacket)

        if self.raw_expiration_time:
            self.expiration_time = self.creation_time + timedelta(
                seconds=self.raw_expiration_time)

    sig_types = {
        0x00: "Signature of a binary document",
        0x01: "Signature of a canonical text document",
        0x02: "Standalone signature",
        0x10: "Generic certification of a User ID and Public Key packet",
        0x11: "Persona certification of a User ID and Public Key packet",
        0x12: "Casual certification of a User ID and Public Key packet",
        0x13: "Positive certification of a User ID and Public Key packet",
        0x18: "Subkey Binding Signature",
        0x19: "Primary Key Binding Signature",
        0x1f: "Signature directly on a key",
        0x20: "Key revocation signature",
        0x28: "Subkey revocation signature",
        0x30: "Certification revocation signature",
        0x40: "Timestamp signature",
        0x50: "Third-Party Confirmation signature",
    }

    @property
    def sig_type(self):
        return self.sig_types.get(self.raw_sig_type, "Unknown")

    @property
    def pub_algorithm(self):
        return self.lookup_pub_algorithm(self.raw_pub_algorithm)

    @property
    def hash_algorithm(self):
        return self.lookup_hash_algorithm(self.raw_hash_algorithm)

    def __repr__(self):
        return "<%s: %s, %s, length %d>" % (
            self.__class__.__name__, self.pub_algorithm,
            self.hash_algorithm, self.length)


class PublicKeyPacket(Packet, AlgoLookup):
    def __init__(self, *args, **kwargs):
        self.pubkey_version = None
        self.fingerprint = None
        self.key_id = None
        self.raw_creation_time = None
        self.creation_time = None
        self.raw_days_valid = None
        self.expiration_time = None
        self.raw_pub_algorithm = None
        self.pub_algorithm_type = None
        self.modulus = None
        self.modulus_bitlen = None
        self.exponent = None
        self.prime = None
        self.group_order = None
        self.group_gen = None
        self.key_value = None

        self.bitlen = None

        # ECC information
        self.raw_oid = None
        self.raw_oid_length = None

        self.oid = None

        super(PublicKeyPacket, self).__init__(*args, **kwargs)

    def parse(self):
        self.pubkey_version = self.data[0]
        offset = 1
        if self.pubkey_version in (2, 3):
            self.raw_creation_time = get_int4(self.data, offset)
            self.creation_time = datetime.utcfromtimestamp(
                self.raw_creation_time)
            offset += 4

            self.raw_days_valid = get_int2(self.data, offset)
            offset += 2
            if self.raw_days_valid > 0:
                self.expiration_time = self.creation_time + timedelta(
                    days=self.raw_days_valid)

            self.raw_pub_algorithm = self.data[offset]
            offset += 1

            offset = self.parse_key_material(offset)
            md5 = hashlib.md5()
            # Key type must be RSA for v2 and v3 public keys
            if self.pub_algorithm_type == "rsa":
                key_id = ('%X' % self.modulus)[-8:].zfill(8)
                self.key_id = key_id.encode('ascii')
                md5.update(get_int_bytes(self.modulus))
                md5.update(get_int_bytes(self.exponent))
            elif self.pub_algorithm_type == "elg":
                # Of course, there are ELG keys in the wild too. This formula
                # for calculating key_id and fingerprint is derived from an old
                # key and there is a test case based on it.
                key_id = ('%X' % self.prime)[-8:].zfill(8)
                self.key_id = key_id.encode('ascii')
                md5.update(get_int_bytes(self.prime))
                md5.update(get_int_bytes(self.group_gen))
            else:
                raise PgpdumpException("Invalid non-RSA v%d public key" %
                                       self.pubkey_version)
            self.fingerprint = md5.hexdigest().upper().encode('ascii')
        elif self.pubkey_version == 4:
            sha1 = hashlib.sha1()
            seed_bytes = (0x99, (self.length >> 8) & 0xff, self.length & 0xff)
            sha1.update(bytearray(seed_bytes))
            sha1.update(self.data)
            self.fingerprint = sha1.hexdigest().upper().encode('ascii')
            self.key_id = self.fingerprint[24:]

            self.raw_creation_time = get_int4(self.data, offset)
            self.creation_time = datetime.utcfromtimestamp(
                self.raw_creation_time)
            offset += 4

            self.raw_pub_algorithm = self.data[offset]
            offset += 1

            offset = self.parse_key_material(offset)
        else:
            raise PgpdumpException(
                "Unsupported public key packet, version %d" % (
                    self.pubkey_version))

        return offset

    def parse_key_material(self, offset):
        if self.raw_pub_algorithm in (1, 2, 3):
            self.pub_algorithm_type = "rsa"
            # n, e
            self.modulus, offset = get_mpi(self.data, offset)
            self.exponent, offset = get_mpi(self.data, offset)
            # the length of the modulus in bits
            self.modulus_bitlen = int(ceil(log(self.modulus, 2)))
            self.bitlen = self.modulus_bitlen
        elif self.raw_pub_algorithm == 17:
            self.pub_algorithm_type = "dsa"
            # p, q, g, y
            self.prime, offset = get_mpi(self.data, offset)
            self.group_order, offset = get_mpi(self.data, offset)
            self.group_gen, offset = get_mpi(self.data, offset)
            self.key_value, offset = get_mpi(self.data, offset)
            # This isn't always accurate, but you can round to the
            # nearest power of 2 yourself.
            self.bitlen = int(ceil(log(self.key_value, 2)))
        elif self.raw_pub_algorithm in (16, 20):
            self.pub_algorithm_type = "elg"
            # p, g, y
            self.prime, offset = get_mpi(self.data, offset)
            self.group_gen, offset = get_mpi(self.data, offset)
            self.key_value, offset = get_mpi(self.data, offset)
        elif self.raw_pub_algorithm == 18:
            self.pub_algorithm_type = "ecc"
            offset = self.parse_oid_data(offset)
        elif self.raw_pub_algorithm == 19:
            self.pub_algorithm_type = "ecdsa"
            offset = self.parse_oid_data(offset)
        elif self.raw_pub_algorithm == 22:
            self.pub_algorithm_type = "curve25519"
            offset = self.parse_oid_data(offset)
        elif 100 <= self.raw_pub_algorithm <= 110:
            # Private/Experimental algorithms, just move on
            pass
        else:
            raise PgpdumpException("Unsupported public key algorithm %d" %
                                   self.raw_pub_algorithm)

        return offset

    def parse_oid_data(self, offset):
        oid_length = self.data[offset]
        offset += 1

        oid = get_hex_data(self.data, offset, oid_length)
        offset += oid_length
        self.raw_oid = oid
        self.raw_oid_length = oid_length

        oid_value = self.lookup_oid(self.raw_oid)
        self.oid = oid_value[0]
        self.bitlen = oid_value[1]

        return offset

    @property
    def pub_algorithm(self):
        return self.lookup_pub_algorithm(self.raw_pub_algorithm)

    def __repr__(self):
        return "<%s: 0x%s, %s, length %d>" % (
            self.__class__.__name__, self.key_id.decode('ascii'),
            self.pub_algorithm, self.length)


class PublicSubkeyPacket(PublicKeyPacket):
    """
    A Public-Subkey packet (tag 14) has exactly the same format as a
    Public-Key packet, but denotes a subkey.
    """
    pass


def new_tag_length(data, start):
    """
    Takes a bytearray of data as input, as well as an offset of where to
    look. Returns a derived (offset, length, partial) tuple.
    Reference: http://tools.ietf.org/html/rfc4880#section-4.2.2
    """
    first = data[start]
    offset = length = 0
    partial = False

    # one-octet
    if first < 192:
        offset = 1
        length = first

    # two-octet
    elif first < 224:
        offset = 2
        length = ((first - 192) << 8) + data[start + 1] + 192

    # five-octet
    elif first == 255:
        offset = 5
        length = get_int4(data, start + 1)

    # Partial Body Length header, one octet long
    else:
        offset = 1
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
    temp_len = data[start] & 0x03

    if temp_len == 0:
        offset = 1
        length = data[start + 1]
    elif temp_len == 1:
        offset = 2
        length = get_int2(data, start + 1)
    elif temp_len == 2:
        offset = 4
        length = get_int4(data, start + 1)
    elif temp_len == 3:
        length = len(data) - start - 1

    return (offset, length)


# Severely trimmed down TAG_TYPES list.
TAG_TYPES = {
    # (Name, PacketType) tuples
    2: ("Signature Packet", SignaturePacket),
    6: ("Public Key Packet", PublicKeyPacket),
}


def construct_packet(data, header_start):
    """
    Returns a (length, packet) tuple constructed from 'data' at index
    'header_start'. If there is a next packet, it will be found at
    header_start + length.
    """

    # tag encoded in bits 5-0 (new packet format)
    # 0x3f == 111111b
    tag = data[header_start] & 0x3f

    # the header is in new format if bit 7 is set
    # 0x40 == 1000000b
    new = bool(data[header_start] & 0x40)

    if new:
        # length is encoded in the second (and following) octet
        data_offset, data_length, partial = new_tag_length(
            data, header_start + 1)
    else:
        # tag encoded in bits 5-2, discard bits 1-0
        tag >>= 2
        data_offset, data_length = old_tag_length(data, header_start)
        partial = False

    name, PacketType = TAG_TYPES.get(tag, ("Unknown", None))
    # Packet type not yet handled
    if not PacketType:
        PacketType = Packet

    # first octet of the packet header handled
    data_offset += 1

    # data consumed to create new packet, consists of header and data
    consumed = 0
    packet_data = bytearray()
    original_data = bytearray()
    while True:
        consumed += data_offset

        data_start = header_start + data_offset
        next_header_start = data_start + data_length
        original_data += data[header_start:next_header_start]
        packet_data += data[data_start:next_header_start]
        consumed += data_length

        # The new format might encode data with Partial Body Length headers.
        # Then a packet consists of alternating header and data regions. The
        # last header of a packet is not a Partial Body Length header.
        if partial:
            data_offset, data_length, partial = new_tag_length(
                data, next_header_start)
            header_start = next_header_start
        else:
            break
    packet = PacketType(tag, name, new, packet_data, original_data)
    return consumed, packet
