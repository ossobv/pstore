# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore-lib -- Python Protected Password Store (Library)
Copyright (C) 2010,2012,2013,2015  Walter Doekes <wdoekes>, OSSO B.V.

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

This module implements a couple of functions to ease reading of OpenSSH public
and private keys and using those keys to encrypt and decrypt short messages.

Note that decrypting encrypted private SSH keys is only implemented for
DES-EDE3-CBC.

The class OAEP and helper function make_mgf1 are taken from PyCrypto
(python-crypto) bug report 328027 (launchpad/pycrypto). The author of that code
is Ryan Kelly (~ryan-rfk).

Dependencies:
* PyCrypto (python-crypto)
* ASN.1 tools for python (python-pyasn1)
"""
from __future__ import absolute_import

from base64 import b16decode, b64decode, b64encode
from hashlib import md5, sha1       # md5 for DES-EDE3-CBC, sha1 for OAEP
from math import ceil
from os import urandom

try:
    import Crypto
    Crypto
except ImportError, e:
    raise ImportError(e.args[0] + '\n\n*HINT* apt-get install python-crypto')

from Crypto.Cipher import DES3      # decrypt DES-EDE3-CBC private key
from Crypto.PublicKey import RSA    # en-/decrypt data stream
from Crypto.Util.number import bytes_to_long, long_to_bytes

try:
    from Crypto.Hash.HMAC import _strxor as strxor
except ImportError:
    try:
        from Crypto.Util.strxor import strxor
    except ImportError:
        from Crypto.Util import strxor

try:
    import pyasn1
except ImportError, e:
    raise ImportError(e.args[0] + '\n\n*HINT* apt-get install python-pyasn1')

try:
    from pyasn1.codec.ber import decoder as asn1decoder
except ImportError:
    from pyasn1.v1.codec.ber import decoder as asn1decoder

from pstorelib.exceptions import (CryptError, CryptBadPassword,
                                  CryptBadPrivKey, CryptBadPubKey)


# Only exposing RSACrypt and SSHKeyParser
__all__ = ('RSACrypt', 'SSHKeyParser')


class SSHKeyParser(object):
    """
    A simple interface to parse SSH public and private keys.
    """
    @staticmethod
    def default_password_cb():
        from getpass import getpass
        return (getpass('Enter passphrase for RSA key: '), True)

    def __init__(self):
        """
        Construct an SSHKeyParser.
        """
        self.password_cb = self.default_password_cb

    def set_password_cb(self, password_cb):
        """
        Set a password callback. Should return (password, allow_caching).
        """
        self.password_cb = password_cb

    def parse_public(self, line):
        """
        Parse a public key line in the ssh-rsa form: "ssh-rsa AAA..."

        Returns a dictionary with RSA variables e and n.
        """
        items = line.split(' ', 2)
        if len(items) == 3:
            type, blob, comment = items
        elif len(items) == 2:
            type, blob = items
        else:
            raise CryptBadPubKey('split failed', line)

        if type != 'ssh-rsa':
            raise CryptBadPubKey('expected type ssh-rsa', type)
        try:
            blob = b64decode(blob)
        except:
            raise CryptBadPubKey('base64 decode failed', blob)

        results = []
        while blob != '':
            length = [long(ord(i)) for i in blob[0:4]]
            length = (length[0] << 24 | length[1] << 16 | length[2] << 8 |
                      length[3])
            part = blob[4:(4 + length)]
            blob = blob[(4 + length):]
            if len(part) != length:
                raise CryptBadPubKey(('elongation failed: expected %d for %d, '
                                      'got %d') %
                                     (length, len(results) + 1, len(part)))
            results.append(part)

        if len(results) != 3:
            raise CryptBadPubKey('expected 3 items in blob, got %d' %
                                 (len(results),), results)
        if results[0] != 'ssh-rsa':
            raise CryptBadPubKey('expected type ssh-rsa in blob, got %s' %
                                 (results[0],), results)

        type = results[0]
        rsa_e = bytes_to_long(results[1])
        rsa_n = bytes_to_long(results[2])

        return {'type': type, 'n': rsa_n, 'e': rsa_e}

    def parse_private(self, text):
        """
        Parse a private key file in the ssh-rsa form: --BEGIN RSA PRIVATE...

        Returns a dictionary with RSA variables n, e, d, p and q.
        """
        lines = text.split('\n')
        del text
        # Strip all from begin until marker.
        while lines[0].strip() != '-----BEGIN RSA PRIVATE KEY-----':
            lines.pop(0)
        lines.pop(0)
        # Strip all from end back to marker.
        while lines[-1].strip() != '-----END RSA PRIVATE KEY-----':
            lines.pop()
        lines.pop()

        # Get base64 data from end and decode to binary.
        data = []
        while len(lines) and lines[-1].strip() != '':
            data.insert(0, lines[-1].strip())
            lines.pop()
        blob = ''.join(data)
        del data

        try:
            blob = b64decode(blob)
        except:
            raise CryptBadPrivKey('base64 decode failed', blob)

        # If there are lines left, they contain encryption info.
        if len(lines):
            if (len(lines) != 3 or
                    lines[2].strip() != '' or
                    not lines[0].startswith('Proc-Type: 4,ENCRYPTED') or
                    not lines[1].startswith('DEK-Info: ')):
                raise CryptBadPrivKey('encryption info parse fail', blob)

            dek_info = lines[1][9:].strip().split(',')
            if len(dek_info) != 2:
                raise CryptBadPrivKey('expected comma-separated DEK-Info',
                                      lines[1])
        else:
            dek_info = None
        del lines

        # ASN.1-decode the blob and get the values. Do it once or three times
        # depending on whether we need to ask for a password.
        for i in range((1, 3)[bool(dek_info)]):
            if dek_info:
                key = self.decrypt(blob, dek_info)
            else:
                key = blob

            if not dek_info and (not key or key[0] != '0'):
                raise CryptBadPrivKey('expected ASN.1 to begin with 0', key)

            try:
                items = asn1decoder.decode(key)
            except pyasn1.error.PyAsn1Error, e:
                if not dek_info:
                    raise CryptBadPrivKey('ASN.1 decode failed',
                                          (': '.join(str(i) for i in e.args)))
            else:
                break
        else:
            # We iterated over dek_info three times while calling decrypt
            # (asking for a password). Still nothing: bad password (or invalid
            # data).
            assert dek_info
            raise CryptBadPassword()

        if long(items[0][0]) != 0:
            raise CryptBadPrivKey('expected pub key version 0', items[0][0])

        type = 'ssh-rsa'
        rsa_n, rsa_e = long(items[0][1]), long(items[0][2])
        rsa_d = long(items[0][3])
        rsa_p, rsa_q = long(items[0][4]), long(items[0][5])

        return {'type': type,               # "ssh-rsa"
                'n': rsa_n, 'e': rsa_e,     # (p * q), exponent
                'd': rsa_d,                 # private key exponent
                'p': rsa_p, 'q': rsa_q}     # two private primes

    def decrypt(self, data, dek_info):
        """
        Decrypt password encrypted private key data (the encrypted ASN.1
        private key data).
        """
        if dek_info[0] != 'DES-EDE3-CBC':
            raise NotImplementedError(('unexpected algorithm %s, expected '
                                       'DES-EDE3-CBC') % (dek_info[0],))

        # Convert hex to binary.
        salt_and_iv = b16decode(dek_info[1])

        # Get password from user.
        password, allow_caching = self.password_cb()
        del allow_caching

        # Convert password to 24 bytes for 3DES.
        des_password = ''
        while len(des_password) < 24:
            tmp = ''
            if len(des_password):
                tmp = des_password
            tmp += password + salt_and_iv
            des_password += md5(tmp).digest()
        des_password = des_password[0:24]

        # Create a 3DES decryptor with the password and initialization vector
        # and decrypt data.
        return DES3.new(des_password, DES3.MODE_CBC, salt_and_iv).decrypt(data)


def make_mgf1(hash):
    """
    Make an MGF1 function using the given hash function.

    Given a hash function implementing the standard hash function interface,
    this function returns a Mask Generation Function using that hash.
    """
    def mgf1(mgfSeed, maskLen):
        """
        Mask Generation Function based on a hash function.

        Given a seed byte string 'mgfSeed', this function will generate
        and return a mask byte string  of length 'maskLen' in a manner
        approximating a Random Oracle.

        The algorithm is from PKCS#1 version 2.1, appendix B.2.1.
        """
        hLen = hash().digest_size
        if maskLen > (2 ** 32) * hLen:
            raise NotImplementedError('mask too long')
        T = ''
        for counter in range(int(ceil(maskLen / float(hLen)))):
            C = long_to_bytes(counter)
            C = ('\x00' * (4 - len(C))) + C
            assert len(C) == 4, 'counter was too big'
            T += hash(mgfSeed + C).digest()
        assert len(T) >= maskLen, 'generated mask was too short'
        return T[:maskLen]
    return mgf1


MGF1_SHA1 = make_mgf1(sha1)


class OAEP(object):
    """
    Class implementing OAEP encoding/decoding.

    This class can be used to encode/decode byte strings using the Optimal
    Asymmetic Encryption Padding Scheme.  It requires a source of random bytes,
    a hash function and a mask generation function.  By default SHA-1 is used
    as the hash function, and MGF1-SHA1 is used as the mask generation
    function.

    The method 'encode' will encode a byte string using this padding scheme,
    and the complementary method 'decode' will decode it.

    The algorithms are from PKCS#1 version 2.1, section 7.1.
    """
    def __init__(self, randbytes=urandom, hash=sha1, mgf=MGF1_SHA1):
        self.randbytes = randbytes
        self.hash = hash
        self.mgf = mgf

    def encode(self, k, M, L=''):
        """
        Encode a message using OAEP.

        This method encodes a byte string 'M' using Optimal Asymmetric
        Encryption Padding.  The argument 'k' must be the size of the private
        key modulus in bytes.  If specified, 'L' is a label for the
        encoding.
        """
        # Calculate label hash, unless it is too long.
        if L:
            limit = getattr(self.hash, 'input_limit', None)
            if limit and len(L) > limit:
                raise CryptError('encrypt label too long')
        lHash = self.hash(L).digest()
        # Check length of message against size of key modulus
        mLen = len(M)
        hLen = len(lHash)
        if mLen > k - 2 * hLen - 2:
            raise CryptError('encrypt message too long')
        # Perform the encoding.
        PS = '\x00' * (k - mLen - 2 * hLen - 2)
        DB = lHash + PS + '\x01' + M
        assert len(DB) == k - hLen - 1, 'DB length is incorrect'
        seed = self.randbytes(hLen)
        dbMask = self.mgf(seed, k - hLen - 1)
        maskedDB = strxor(DB, dbMask)
        seedMask = self.mgf(maskedDB, hLen)
        maskedSeed = strxor(seed, seedMask)
        return '\x00' + maskedSeed + maskedDB

    def decode(self, k, EM, L=''):
        """
        Decode a message using OAEP.

        This method decodes a byte string 'EM' using Optimal Asymmetric
        Encryption Padding.  The argument 'k' must be the size of the private
        key modulus in bytes.  If specified, 'L' is the label used for the
        encoding.
        """
        # Generate label hash, for sanity checking.
        lHash = self.hash(L).digest()
        hLen = len(lHash)
        # Split the encoded message.
        Y = EM[0]
        maskedSeed = EM[1:(hLen + 1)]
        maskedDB = EM[(hLen + 1):]
        # Perform the decoding.
        seedMask = self.mgf(maskedDB, hLen)
        seed = strxor(maskedSeed, seedMask)
        dbMask = self.mgf(seed, k - hLen - 1)
        DB = strxor(maskedDB, dbMask)
        # Split the DB string.
        lHash1 = DB[:hLen]
        x01pos = hLen
        while x01pos < len(DB) and DB[x01pos] != '\x01':
            x01pos += 1
        M = DB[(x01pos + 1):]
        # All sanity-checking done at end, to avoid timing attacks.
        valid = True
        if x01pos == len(DB):  # No \x01 byte
            valid = False
        if lHash1 != lHash:    # Mismatched label hash
            valid = False
        if Y != '\x00':        # Invalid leading byte
            valid = False
        if not valid:
            raise CryptError('decrypt de-padding failed validation')
        return M


class RSACrypt(object):
    """
    Wrapper around RSA encrypting/decrypting.

    It uses "default" OAEP padding for the data.
    """
    def __init__(self, n, e, d=None, p=None, q=None):
        # From: https://www.dlitz.net/software/pycrypto/api/current/ _
        #         Crypto.PublicKey.RSA.RSAImplementation-class.html#construct
        #
        # Construct an RSA key object from a tuple of valid RSA components.
        #
        # The modulus n must be the product of two primes. The public exponent
        # e must be odd and larger than 1.
        #
        # In case of a private key, the following equations must apply:
        # - e != 1
        # - p*q = n
        # - e*d = 1 mod (p-1)(q-1)
        # - u = inverse of p mod q.
        # - p*u = 1 mod q
        #
        # Parameters:
        # - n = RSA modulus
        # - e = Public exponent
        # - d = Private exponent (only required if the key is private)
        # - p = First factor of n (optional)
        # - q = Second factor of n (optional)
        #
        if d:
            self.rsa = RSA.construct((n, e, d, p, q))
        else:
            self.rsa = RSA.construct((n, e))

        # Get modulus length for encoder.
        self.padlen = len(long_to_bytes(n))
        # The padder is optional, but preferable. It:
        # (1) Adds an element of randomness which can be used to convert a
        # deterministic encryption scheme (e.g., traditional RSA) into a
        # probabilistic scheme.
        # (2) Prevents partial decryption of ciphertexts (or other information
        # leakage) by ensuring that an adversary cannot recover any portion of
        # the plaintext without being able to invert the trapdoor one-way
        # permutation .
        self.padder = OAEP()

    def encrypt(self, data):
        """
        Encrypt the data.
        """
        if self.padder:
            data = self.padder.encode(self.padlen, data)
            assert data[0] == '\x00', 'Expected leading 0-byte from OAEP'
        results = self.rsa.encrypt(data, '')
        assert len(results) == 1
        return results[0]

    def decrypt(self, data):
        """
        Decrypt the data.
        """
        result = self.rsa.decrypt((data,))

        if self.padder:
            # Must pad data back to padlen (see assertion above). Note that
            # unencoded binary data suffers from the same problem.
            result = self.padder.decode(self.padlen,
                                        result.rjust(self.padlen, '\x00'))
        return result


if __name__ == '__main__':
    import unittest

    class Test(unittest.TestCase):
        maxDiff = None
        unencrypted_key = (
            '''-----BEGIN RSA PRIVATE KEY-----
            MIICWwIBAAKBgQDQhys3JAt1XIKClC0x+//SqdEpa3BkYvZF8vOddDngS6gibhvD
            mWkJ58z1i1917TTj4Hj0bbkK81hJ2JFMdROJhtffMOtmO6ibsy/GFJ+h170euVgW
            cLsVhj6o6hYJkvNaODXoC2NU4O26k3uiYb/iN7/R3tq6ojDloYQjhHpMiwIBIwKB
            gQCa6BF5azu2RLi4xdhuRivBEG992siFFlCLu8rp/pFkynzmYGxlaqXM2BSZJbSg
            vtbVKmh7D64IInwZmZCB8JIqTrj0s3qMzjNHG93Qwp5tEvQaCiBysrg8if5/n0ni
            FiaOXFEbYFc0b2FrOPo0MbWrbF6oTIcuryoNjzARASUx+wJBAOgtLwmsefLParMY
            ZnwToRG4CUTWOl5lqnSg3er29YNTw/fiTe5gSaRbhCfm90gYiBHOa2gliTHcyk5S
            WkWwIu0CQQDl7Mk1o8xG9qALzzy58dBnlRnJVi36XWhX2uQe2SijCTkS0rovA85/
            QE13fu6vWi52hatKxCPTTLpNhMYMBGZXAkEAsxuKr7DwXDmbdDdlAKFtn/Re6/W3
            /62Dfoq50oP/OWyBO5FSD6ldYYhtQ1pm/Ro9FQzzxV7I6/N3fj+Hd5aBVwJATtTX
            RZc+uT6dReCnGy5WFOKpwV9gOJUN1PqXWwigN+Xnrq6mPAFOHQAaj164PB7rW9YO
            1844KzA/4BBD5tzv4wJAOEQodXRqV2nAB4PvvKJSqgf5V33MUs0ihRPcDp7cJpNJ
            U51Ole+usiLLZCWLgaW8Excsr+UGicdOQTIAxm4OPQ==
            -----END RSA PRIVATE KEY-----'''.replace('  ', ''),
            '''ssh-rsa\x20
            AAAAB3NzaC1yc2EAAAABIwAAAIEA0IcrNyQLdVyCgpQtMfv/0qnRKWtwZGL2RfLz
            nXQ54EuoIm4bw5lpCefM9Ytfde004+B49G25CvNYSdiRTHUTiYbX3zDrZjuom7Mv
            xhSfode9HrlYFnC7FYY+qOoWCZLzWjg16AtjVODtupN7omG/4je/0d7auqIw5aGE
            I4R6TIs= abc@example.com'''.replace('  ', '').replace('\n', '')
        )
        encrypted_key = (
            '''-----BEGIN RSA PRIVATE KEY-----
            Proc-Type: 4,ENCRYPTED
            DEK-Info: DES-EDE3-CBC,9C514622E5E171E5

            KkqpzaQRbUfI9gFORshyZFvMy6oF/qEG69ctqXSl09PrWaQDMF5FVFRR2Yq5Rzi/
            mIB4EhgTAM55bWgtD3o2kDpLXfIWauvuu20W37NH87Y4JgDI+No457THmESfRCF8
            +HpYgl5yM19cy90zSUGzGpZmkSK9sg4xi+Yy6RNhUbsS9x1QLAjV1dsDYWXroCGZ
            6q7S3Nl6W0KwS5r8wOEnG+gkGb9i6wvjcG7VfMVDHleVw6fdeSy725iuLPtw3h71
            eavBy0WuUQAYv9yOMCa4IilU7c7dcGRU4g521ayydTbku9Kv+Ck/J6aug9MV84yq
            Irt++O0361ZtklrE1CdhdPCDzfEis4Bg8yjJnLO94AlT8mfjT1UyZFlbI2eYU+5o
            EF6GGU/dwxaD7OUeM2bbjZnYr6rCXA0iy8rBckIMHAUrC60u63ExhpB56C6ep6if
            dAZAbPhyQ+yRO6hbcJZglwUs9a627WFvyyv91gU5Nt67DoJni6DsjI2A44p0wcPm
            zZ26HDH2JAWB7GTFVELWWFP2lGJPBIjOQfN0n/Ktu/IPRScKWdZtYoyJAK1JHh28
            s6TW6X71a1vdv9Taf+/1c5ftXTi6sLHIQbgQHdwwBK2RLs9m2eNwqMYN9LQBkC9E
            bhx3Mv1V9WlAQsU5h0p0S/xUU1dKJYyFtQ7WOQitEl3cyNCQeuFFuljb8fV7Aj9U
            9hafrrX4YNByGegWA4d6mvSEqSJVX5QFZjLjeG18OKzs/ZwLAKsVc7Jbf1GmC9bn
            gg91NY26as/VkQo5YaBIfsOEPwOVK9PavLy5maJQdzc=
            -----END RSA PRIVATE KEY-----'''.replace('  ', ''),
            '''ssh-rsa\x20
            AAAAB3NzaC1yc2EAAAABIwAAAIEAqxSM3t3iX4OSBBgfXnFmFjQ0kYiHpQrgKfPb
            d7BuMVeT6BGp/+4l2ZIq9xEQF4J5mdEHuyAJrHdFRq7if5+OiGUuGOVEnAfzWjHg
            vErranLZo+6XRMsnvMG6DiD/Ys+uySw7tFw3mxzDgNxYbXaTc/Bbnqy6hi7/JSfX
            AqjSqKE= def@example.com'''.replace('  ', '').replace('\n', '')
        )

        def bignum(self, value):
            return bytes_to_long(b64decode(value))

        def test_bignum(self):
            input = 1234567890123456789012345678901234567890L
            text = b64encode(long_to_bytes(input))
            output = self.bignum(text)
            self.assertEqual(output, input)

        def test_OAEP_1(self):
            oaep = OAEP()
            data = 'Hello world!'
            enc1 = oaep.encode(128, data)
            enc2 = oaep.encode(128, data)
            # The random generator in OAEP should ensure that enc1 != enc2
            self.assertNotEqual(enc1, enc2)
            # But the unencoded contents should be the same.
            dec1 = oaep.decode(128, enc1)
            dec2 = oaep.decode(128, enc2)
            self.assertEqual(dec1, dec2)
            self.assertEqual(dec2, data)

        def test_OAEP_2(self):
            input = ('AMoc98M5otEvaSpqxhxw873WHo0R7HLmQuSMnhZDGRASDmCnjk+O82wW'
                     'GJiBAZH63rnzEDs0RMCbBhfd+9RdESVK1qhYq98T/vJDvWRT/qgvqHg3'
                     'aigkHQ9tcCmF3qDGRgxiTpeDwm+I42HYa3M+jZtKvHKX68qlYSd//Wnp'
                     'lKk=')
            enc = b64decode(input)
            oaep = OAEP()
            dec = oaep.decode(128, enc)
            self.assertEqual(dec, 'Hello world!')

        def test_parse_public_ssh_key_1(self):
            parser = SSHKeyParser()
            ret = parser.parse_public(self.unencrypted_key[1])
            self.assertEqual(ret, {
                'type': 'ssh-rsa',
                'n': self.bignum('''
                    0IcrNyQLdVyCgpQtMfv/0qnRKWtwZGL2RfLznXQ54EuoIm4bw5lpCefM9Y
                    tfde004+B49G25CvNYSdiRTHUTiYbX3zDrZjuom7MvxhSfode9HrlYFnC7
                    FYY+qOoWCZLzWjg16AtjVODtupN7omG/4je/0d7auqIw5aGEI4R6TIs=
                '''),
                'e': 35L,
            })

        def test_parse_public_ssh_key_2(self):
            parser = SSHKeyParser()
            ret = parser.parse_public(self.encrypted_key[1])
            self.assertEqual(ret, {
                'type': 'ssh-rsa',
                'n': self.bignum('''
                    qxSM3t3iX4OSBBgfXnFmFjQ0kYiHpQrgKfPbd7BuMVeT6BGp/+4l2ZIq9xE
                    QF4J5mdEHuyAJrHdFRq7if5+OiGUuGOVEnAfzWjHgvErranLZo+6XRMsnvM
                    G6DiD/Ys+uySw7tFw3mxzDgNxYbXaTc/Bbnqy6hi7/JSfXAqjSqKE=
                '''),
                'e': 35L,
            })

        def test_parse_private_ssh_key_1(self):
            parser = SSHKeyParser()
            ret = parser.parse_private(self.unencrypted_key[0])
            self.assertEqual(ret, {
                'type': 'ssh-rsa',
                'n': self.bignum('''
                    0IcrNyQLdVyCgpQtMfv/0qnRKWtwZGL2RfLznXQ54EuoIm4bw5lpCefM9Yt
                    fde004+B49G25CvNYSdiRTHUTiYbX3zDrZjuom7MvxhSfode9HrlYFnC7FY
                    Y+qOoWCZLzWjg16AtjVODtupN7omG/4je/0d7auqIw5aGEI4R6TIs=
                '''),
                'e': 35L,
                'd': self.bignum('''
                    mugReWs7tkS4uMXYbkYrwRBvfdrIhRZQi7vK6f6RZMp85mBsZWqlzNgUmSW
                    0oL7W1Spoew+uCCJ8GZmQgfCSKk649LN6jM4zRxvd0MKebRL0GgogcrK4PI
                    n+f59J4hYmjlxRG2BXNG9hazj6NDG1q2xeqEyHLq8qDY8wEQElMfs=
                '''),
                'p': self.bignum('''
                    6C0vCax58s9qsxhmfBOhEbgJRNY6XmWqdKDd6vb1g1PD9+JN7mBJpFuEJ+b
                    3SBiIEc5raCWJMdzKTlJaRbAi7Q==
                '''),
                'q': self.bignum('''
                    5ezJNaPMRvagC888ufHQZ5UZyVYt+l1oV9rkHtkoowk5EtK6LwPOf0BNd37
                    ur1oudoWrSsQj00y6TYTGDARmVw==
                '''),
            })

        def test_parse_private_ssh_key_2(self):
            parser = SSHKeyParser()
            parser.set_password_cb((lambda: ('testtest', False)))
            ret = parser.parse_private(self.encrypted_key[0])
            self.assertEqual(ret, {
                'type': 'ssh-rsa',
                'n': self.bignum('''
                    qxSM3t3iX4OSBBgfXnFmFjQ0kYiHpQrgKfPbd7BuMVeT6BGp/+4l2ZIq9xE
                    QF4J5mdEHuyAJrHdFRq7if5+OiGUuGOVEnAfzWjHgvErranLZo+6XRMsnvM
                    G6DiD/Ys+uySw7tFw3mxzDgNxYbXaTc/Bbnqy6hi7/JSfXAqjSqKE=
                '''),
                'e': 35L,
                'd': self.bignum('''
                    l4c68Ugu5uI/f/gbyK2U7xhL0VurV6qMB+ad0GkRJGODAL8wK9LuUv3OSIt
                    0pxvKyhDplxxgVu1L/MbInOxoS3kADYKzbyga0JI3klJmQ9R1yqZcIspjuC
                    sbT7Nu5M0CYo3qiW+o/aLpzdg1BMc3pDDeJ1T3m5aNubzpZv3TGfs=
                '''),
                'p': self.bignum('''
                    1/pyyGEfYSV3RN7j94GRJVGlwuRqUYwLGgD2pmIyJXJ6CHml1KzZAFv+mLn
                    dUt90gSsTDWR/SLv6gok+vgflzQ==
                '''),
                'q': self.bignum('''
                    ysg8BTGskkyD1E99ckC2AtF0NhEFxqb6f0/vCt3sRucJKLD/vybNCaGZ2+b
                    VETte1OtneTY2NAZAKtrkSBY6JQ==
                '''),
            })

        def test_rsawrapper(self):
            data = 'Hello world!'
            crypt = RSACrypt(
                n=self.bignum('''
                    qxSM3t3iX4OSBBgfXnFmFjQ0kYiHpQrgKfPbd7BuMVeT6BGp/+4l2ZIq9xE
                    QF4J5mdEHuyAJrHdFRq7if5+OiGUuGOVEnAfzWjHgvErranLZo+6XRMsnvM
                    G6DiD/Ys+uySw7tFw3mxzDgNxYbXaTc/Bbnqy6hi7/JSfXAqjSqKE=
                '''),
                e=35L
            )

            # With the OAEP() padder the output is in (127, 128). Without it,
            # it's 128.
            encrypted = crypt.encrypt(data)
            self.assertTrue(len(encrypted) in (127, 128))

            crypt = RSACrypt(
                n=self.bignum('''
                    qxSM3t3iX4OSBBgfXnFmFjQ0kYiHpQrgKfPbd7BuMVeT6BGp/+4l2ZIq9xE
                    QF4J5mdEHuyAJrHdFRq7if5+OiGUuGOVEnAfzWjHgvErranLZo+6XRMsnvM
                    G6DiD/Ys+uySw7tFw3mxzDgNxYbXaTc/Bbnqy6hi7/JSfXAqjSqKE=
                '''),
                e=35L,
                d=self.bignum('''
                    l4c68Ugu5uI/f/gbyK2U7xhL0VurV6qMB+ad0GkRJGODAL8wK9LuUv3OSIt
                    0pxvKyhDplxxgVu1L/MbInOxoS3kADYKzbyga0JI3klJmQ9R1yqZcIspjuC
                    sbT7Nu5M0CYo3qiW+o/aLpzdg1BMc3pDDeJ1T3m5aNubzpZv3TGfs=
                '''),
                p=self.bignum('''
                    1/pyyGEfYSV3RN7j94GRJVGlwuRqUYwLGgD2pmIyJXJ6CHml1KzZAFv+mLn
                    dUt90gSsTDWR/SLv6gok+vgflzQ==
                '''),
                q=self.bignum('''
                    ysg8BTGskkyD1E99ckC2AtF0NhEFxqb6f0/vCt3sRucJKLD/vybNCaGZ2+b
                    VETte1OtneTY2NAZAKtrkSBY6JQ==
                ''')
            )
            decrypted = crypt.decrypt(encrypted)
            self.assertEqual(decrypted, data)

    unittest.main()
