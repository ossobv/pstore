# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore-lib -- Python Protected Password Store (Library)
Copyright (C) 2012,2013,2015,2018  Walter Doekes <wdoekes>, OSSO B.V.

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
"""
from base64 import b64decode
from io import BytesIO
from unittest import TestCase

from pstorelib.crypt import CryptoReader, CryptoWriter, PStoreCrypt


class Test(TestCase):
    ALEX_PUBKEY = ('''
        -----BEGIN PGP PUBLIC KEY BLOCK-----
        Version: GnuPG v1.4.11 (GNU/Linux)

        mI0EULkrQAEEAKU++49M+QfiSTFJjWQ8Yyr+OKa0V90aNGbYNaGvfzlPVHNS+AwR
        PTT56yNEJAbGOFEj4aEYxa/puUJP6CZGtDvQn8FlqZ5zgKHXCRSToIVQLJjZLT3M
        Aqqkt7dCGT/nZCXASurT6zFMgR1eo3u4F3Ur5pYeLmnTUtTqC2yIrnTrABEBAAG0
        J0FsZXggQm9vbnN0cmEgKFRFU1QpIDxhbGV4QGV4YW1wbGUuY29tPoi4BBMBAgAi
        BQJQuStAAhsvBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRDHl9Gl3Z236/Nw
        A/9mUbXuxDWyZsvbkqEpDJv+PjmMZ6Hk99LzSXqPomJZw0TRWmwGFRuhwl4reOXd
        fWMLfXYcrig/vNpcWmPH+1aU2yf+5wnpiGP0AzHyiarmX3smnvmMPrA8wk7F/ml3
        izheBc4+kzIWdK35QHzVzTTMjFsACQKbXAKBvO2VZb7WDLiNBFC5K0ABBAComc00
        /AE+yoO6loMzEuro1sb/HBxkH5wH8CXje3lw2TOBWf4jEW5EzPVZOpRRqfr9/2hf
        ld4GFt02ecHSe+Qk1mcaWpIUoudm/K93NH2yKaCtPFlJ+jV6qwqEG2d9LGEIVrPP
        XP9/EU75EGWOq7XOy2eIHpZOc43JOKjsuRnf9wARAQABiQE9BBgBAgAJBQJQuStA
        AhsuAKgJEMeX0aXdnbfrnSAEGQECAAYFAlC5K0AACgkQpCCsUhak5FudVAQAoqYX
        5O6Or12+jyJgCdf7oNmiuxRpMSuI2AHeSXvxFIkYrKnRyN90g9Cpg/VQtChfe9ks
        KrYzHFxS2I83Yc8j7Tw0GFqghUqFpwdzMleX6vRwBAfYzRjn+Q5lMRt5F4JUVBGN
        2fR+r9apIwpwrmztB/pqAtqW3ULXfFwOZid8ddjPnAP+LDRBMzsWTdvLcYjlh45E
        hpz5BcK9ocJTth8LfISo7eaAq80hqBcROhxegfW7o30K40TfUl5XLNBR1rV+IqSQ
        4/INWgwGTLFwwvHNNbkcNh6GbwQSMPUrV9v2MCw9K/gYHPIZl58bySm8wziElY7I
        YfZlrgW5q6LkcEoYOni58yQ=
        =XD13
        -----END PGP PUBLIC KEY BLOCK-----
    ''').strip()

    ALEX_PRIVKEY = None  # must be in gpg key chain

    def setUp(self):
        PStoreCrypt.create(askpass=PStoreCrypt.ASKPASS_USERNAME2)

    def tearDown(self):
        PStoreCrypt.destroy()

    def test_decrypts_gpg(self):
        input = (b'hIwDpCCsUhak5FsBA/46Fi5ubNMPWRHAiPZdoWrazqhJfg9y9+vAK2'
                 b'vheNWVkpjIXvCExwzgaTmSyghbkh1SI44gybNo0RoTD/a/HxIkxN+A'
                 b'EcD1+XVYOhGjUcWeS8hOk1aSmlt0caaunLUphJuN2i0v5EnomxK3ZD'
                 b'qM9EyXIIsVeQxWDeDYMKEaC0Yp+9JMAWC9489HCPjwwPuyhn3Xn1Lj'
                 b'X2EWOL0pSIuYrBrDba3i56z7teTTMsc69qqta5k/52OAKHzR+Evh4E'
                 b'lUlI/JSIptkz8GkXalBxFLuA==')
        input = b64decode(input)
        decrypted = decrypts(input, type='gpg')
        self.assertEqual(decrypted, b'mySuperSecret!')

    def test_encrypts_gpg(self):
        input = b'mySuperSecret!'
        encrypted = encrypts(input, self.ALEX_PUBKEY)
        self.assertNotEqual(encrypted, input)  # output changes at will

    def test_encrypts_decrypts_gpg(self):
        input = b"is it john doe's birth day?"
        encrypted = encrypts(input, self.ALEX_PUBKEY)
        self.assertNotEqual(encrypted, input)  # output changes at will
        decrypted = decrypts(encrypted, type='gpg')
        self.assertEqual(decrypted, input)

    def test_cryptowriter_none(self):
        source = b'no encryption'
        # The writer should support writing multiple times.
        writer = CryptoWriter(data=source)
        self.assertEqual(writer.encrypt_with(None).read(), source)
        self.assertEqual(writer.encrypt_with(None).read(), source)
        writer = CryptoWriter(fp=BytesIO(source))
        self.assertEqual(writer.encrypt_with(None).read(), source)
        self.assertEqual(writer.encrypt_with(None).read(), source)

    def test_cryptoreader_none(self):
        source = b'no encryption'
        reader = CryptoReader(data=source, enctype='none')
        self.assertEqual(reader.decrypt_with().read(), source)
        reader = CryptoReader(fp=BytesIO(source), enctype='none')
        self.assertEqual(reader.decrypt_with().read(), source)

    def test_cryptoreader_gpg(self):
        source = b'gpg encrypted'
        encrypted = ('hIwDpCCsUhak5FsBA/9DeiA9hg+bQUGnkE4OeW1btR0SWr2Pt'
                     'sP5O8YgEh+ZcZRB/kQlHdaV580+bttXtmU3KE30d6KWMADWqI'
                     'hlLXR3Rk7ZswsgN59u8U2IaEuAR15M8rPS7dEFz4JT3Jic+zJ'
                     'QjJstPkiWxmkdndkP2cemWEXrXuIKXs/iY45DF+/iH9JLATnn'
                     'hGZOpDpya+3jFVMkEghaWwKnvrTQLElMwuyLEf49c5uY9khQF'
                     '3k49/hGTmRbzGqrEQm0zY220OISBqVkdiFUYNDI/EKeFVaw')
        encrypted = b64decode(encrypted)
        reader = CryptoReader(data=encrypted, enctype='gpg')
        self.assertEqual(reader.decrypt_with().read(), source)
        reader = CryptoReader(fp=BytesIO(encrypted), enctype='gpg')
        self.assertEqual(reader.decrypt_with().read(), source)

    def test_streamed_cryptowriter_and_reader(self):
        class ReadOnce(object):
            """Simulate a stream object that does not have seek."""
            def __init__(self, content):
                self.content = content

            def read(self, size=None):
                if size is None:
                    size = len(self.content)
                else:
                    assert size > 0
                ret = self.content[0:size]
                self.content = self.content[size:]
                return ret

        source = b'a bit of data'

        writer = CryptoWriter(fp=ReadOnce(source))
        fp1 = writer.encrypt_with(self.ALEX_PUBKEY)

        reader = CryptoReader(fp=fp1, enctype='gpg')
        decfp = reader.decrypt_with()
        self.assertEqual(decfp.read(), source)


def decrypts(encrypted, type):
    """
    Decrypt ``encrypted`` (a ``str`` (byte string) instance containing
    encrypted data) to a bytestring.

    Encryption type ``type`` must be 'gpg'.

    Called ``decrypts`` and not ``decrypt`` because of its similarity with
    ``pickle.loads()`` which also takes a byte string.

    Can raise a ``CryptError``.

    NOTE: This function is not used by pstore at the moment. But it exists to
    complement encrypts which is used.
    """
    obj = CryptoReader(data=encrypted, enctype=type)
    file = obj.decrypt_with()
    return file.read()


def encrypts(unencrypted, public_key):
    """
    Encrypt ``unencrypted`` (a ``str`` (byte string) instance) as a byte string
    using ``public_key`` as public key.

    The ``public_key`` must be a human readable public key of the GPG/PGP type.

    Called ``encrypts`` and not ``encrypt`` because of its similarity with
    ``pickle.dumps()`` which also returns a byte string.
    """
    obj = CryptoWriter(data=unencrypted)
    file = obj.encrypt_with(public_key)
    return file.read()
