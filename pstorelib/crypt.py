# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore-lib -- Python Protected Password Store (Library)
Copyright (C) 2012,2013,2015  Walter Doekes <wdoekes>, OSSO B.V.

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
from __future__ import absolute_import

from io import UnsupportedOperation
from os import fdopen
# TODO: make a SecureSpooledTemporaryFile that cleans up better after itself?
from tempfile import SpooledTemporaryFile

from pstorelib.bytes import BytesIO, can_seek, get_size, sendfile
from pstorelib.exceptions import CryptBadPrivKey


# We do late importing of pstorelib.gpg and pstorelib.sshrsa. That way you can
# get away with fetching only the libs that you need if you only use one of the
# encryption methods. (Perhaps not needed for those libs directly, but for the
# dependencies of those libs.)

# P.S. The API in this file sucks. We'll need to sort that. FIXME :)


MAX_INMEMORY_SIZE = 1048576  # 1MB or we switch to tempfiles


class PStoreCrypt(object):
    """
    XXX: document me, XXX: rename me: CryptoGlobal? CryptoStore?

    This is a singleton.
    """
    instance = None

    ASKPASS_DEFAULT = 1     # use default password callback
    ASKPASS_NEVER = 2       # do not ask for password
    ASKPASS_USERNAME2 = 3   # return username + '2' as password (for tests)

    @classmethod
    def create(cls, *args, **kwargs):
        """
        Must be called before doing anything with it.
        """
        assert not cls.instance
        cls.instance = cls(*args, **kwargs)

    @classmethod
    def destroy(cls):
        """
        The automated test uses this. You don't need it.
        """
        del cls.instance
        cls.instance = None

    @classmethod
    def get(cls):
        """
        Get the only instance.
        """
        assert cls.instance
        return cls.instance

    def __init__(self, askpass=None, sshrsa_privkey_file=None):
        self.askpass = askpass or self.ASKPASS_DEFAULT
        self.sshrsa_privkey_file = sshrsa_privkey_file

    @property
    def sshrsa_privkey(self):
        """
        Can raise a CryptBadPassword or CryptBadPrivKey.
        """
        if not hasattr(self, '_sshrsa_privkey'):
            if isinstance(self.sshrsa_privkey_file, basestring):
                try:
                    file = open(self.sshrsa_privkey_file, 'r')
                    try:
                        key_data = file.read()
                    finally:
                        file.close()
                except Exception, e:
                    raise CryptBadPrivKey('filesystem error', e)
            else:
                try:
                    key_data = self.sshrsa_privkey_file.read()
                except Exception, e:
                    raise CryptBadPrivKey('file error', e)

            # The keyparser can ask for a password if needed.
            from pstorelib import sshrsa
            parser = sshrsa.SSHKeyParser()

            # Non-interactive use? Automated tests?
            if self.askpass == self.ASKPASS_NEVER:
                parser.set_password_cb((lambda *args: ('', False)))
            elif self.askpass == self.ASKPASS_USERNAME2:
                parser.set_password_cb((lambda name, *args: (name + '2',
                                                             False)))

            self._sshrsa_privkey = parser.parse_private(key_data)
        return self._sshrsa_privkey


class CryptoWriter(object):
    """
    XXX: document this...
    """
    def __init__(self, data=None, fp=None, length=-1):
        assert bool(data is not None) ^ bool(fp)

        if length == -1:
            if data is not None:
                length = len(data)
            else:
                length = get_size(fp)  # can be -1

        # We allow writer reuse, but if we're working with a stream, we cannot
        # seek. Copy the data to a tempfile.
        if fp and not can_seek(fp):
            newfp = SpooledTemporaryFile(MAX_INMEMORY_SIZE)
            sendfile(newfp, fp)
            length = newfp.tell()
            newfp.seek(0)
            fp = newfp

        self.data = data
        self.fp = fp
        self.fpreads = 0        # keep track of fp usage
        self.length = length

        assert length >= 0
        self.use_tempfile = (length > MAX_INMEMORY_SIZE)

    def _get_enctype(self, public_key):
        if public_key is None:
            return 'none'
        elif public_key.startswith('ssh-rsa '):
            return 'sshrsa'
        elif public_key.startswith('----'):
            return 'gpg'
        raise NotImplementedError('unknown public key type', public_key)

    def encrypt_with(self, public_key):
        """
        May raise one of the CryptErrors.
        """
        # We *could* defer encryption until the first read() call is done on
        # the outputted value. But I don't see any benefits.

        # Make sure that a reused Writer provides the right info.
        if self.fp:
            if self.fpreads > 0:
                self.fp.seek(0)  # if this breaks, we didn't init fp properly
            self.fpreads += 1

        enctype = self._get_enctype(public_key)

        if enctype == 'none':
            return self._encrypt_with_none()
        elif enctype == 'gpg':
            return self._encrypt_with_gpg(public_key)
        elif enctype == 'sshrsa':
            return self._encrypt_with_sshrsa(public_key)
        raise NotImplementedError('unknown encryption type')

    def _encrypt_with_none(self):
        if self.fp:
            # Return a new file so they're not closing ours.
            try:
                fileno = self.fp.fileno()
            except UnsupportedOperation:
                newfp = SpooledTemporaryFile(MAX_INMEMORY_SIZE)
                sendfile(newfp, self.fp)
                newfp.seek(0)
                return newfp
            else:
                return fdopen(fileno, 'rb')
        else:
            # For no encryption, passing around a BytesIO is no extra effort if
            # the data already was a string.
            return BytesIO(self.data)

    def _encrypt_with_gpg(self, public_key):
        from pstorelib import gpg
        gpgcrypt = gpg.GPGCrypt()
        gpgkey = gpgcrypt.import_key(public_key)

        if self.fp:
            input = self.fp
        else:
            input = BytesIO(self.data)
        if self.use_tempfile:
            output = SpooledTemporaryFile(MAX_INMEMORY_SIZE)
        else:
            output = BytesIO()

        gpgcrypt.encrypt(input=input, output=output, public_key_ref=gpgkey)
        return output

    def _encrypt_with_sshrsa(self, public_key):
        from pstorelib import sshrsa
        parser = sshrsa.SSHKeyParser()
        key = parser.parse_public(public_key)
        crypt = sshrsa.RSACrypt(n=key['n'], e=key['e'])

        if self.fp:
            input = self.fp.read()
        else:
            input = self.data

        # NOTE: We're not doing tempfiles here.. the sshrsa encryption method
        # is currently limited to very few bytes anyway.
        return BytesIO(crypt.encrypt(input))


class CryptoReader(object):
    """
    XXX: document this...
    """
    def __init__(self, data=None, fp=None, length=-1, enctype='none'):
        assert bool(data is not None) ^ bool(fp)

        if length == -1:
            if data is not None:
                length = len(data)
            else:
                length = get_size(fp)  # can be -1

        # We accept that we can only read it once.
        # if fp and not can_seek(fp): dont_care()

        self.data = data
        self.fp = fp
        self.fpreads = 0    # keep track of fp usage
        self.length = fp

        assert enctype in ('none', 'gpg', 'sshrsa')
        self.enctype = enctype

        self.use_tempfile = (length == -1 or length > MAX_INMEMORY_SIZE)

    def _get_enctype(self):
        return self.enctype

    def _get_password_cb(self):
        # Alter behaviour or the get-password-callback. For certain automatic
        # operations we don't want to ask for anything. If a password is
        # needed: too bad. And for automated tests, we want to return the
        # username + '2' as the default password.
        # (Always returning false for "caching", because it would dump
        # notices on stderr, which we don't need when testing.)
        cryptconf = PStoreCrypt.get()  # FIXME: allow this to fail?
        if cryptconf.askpass == cryptconf.ASKPASS_NEVER:
            return (lambda username, prev_was_bad: ('', False))
        elif cryptconf.askpass == cryptconf.ASKPASS_USERNAME2:
            return (lambda username, prev_was_bad: (username + '2', False))
        return None  # use default

    def decrypt_with(self, private_key):
        """
        May raise one of the CryptErrors.
        """
        # We *could* defer encryption until the first read() call is done on
        # the outputted value. But I don't see any benefits.

        # Make sure that a reused Reader provides the right info.
        if self.fp:
            if self.fpreads > 0:
                self.fp.seek(0)  # if this breaks, we didn't init fp properly
            self.fpreads += 1

        enctype = self._get_enctype()

        if enctype == 'none':
            assert private_key is None
            return self._decrypt_with_none()
        elif enctype == 'gpg':
            assert private_key is None
            return self._decrypt_with_gpg()
        elif enctype == 'sshrsa':
            return self._decrypt_with_sshrsa(private_key)
        raise NotImplementedError('unknown encryption type')

    def _decrypt_with_none(self):
        if self.fp:
            # Safe, until someone starts re-reading none-encrypted data.
            return self.fp
        else:
            # For no decryption, passing around a BytesIO is no extra effort if
            # the data already was a string.
            return BytesIO(self.data)

    def _decrypt_with_gpg(self):
        from pstorelib import gpg
        gpgcrypt = gpg.GPGCrypt()

        # Alter get-password-callback in some cases.
        password_cb = self._get_password_cb()
        if password_cb:
            def password_cb_wrapper(id_name_comment_email, key_ids,
                                    prev_was_bad):
                username = id_name_comment_email.rsplit('<', 1)[1]
                username = username.split('@', 1)[0]
                return password_cb(username, prev_was_bad)
            gpgcrypt.set_password_cb(password_cb_wrapper)

        # GPG doesn't need a decryption recipient. It finds one in your
        # secret keyring automatically. (No need to pass a private key
        # manually.)
        if self.fp:
            input = self.fp
        else:
            input = BytesIO(self.data)
        if self.use_tempfile:
            output = SpooledTemporaryFile(MAX_INMEMORY_SIZE)
        else:
            output = BytesIO()

        gpgcrypt.decrypt(input=input, output=output)
        return output

    def _decrypt_with_sshrsa(self, private_key):
        from pstorelib import sshrsa

        # Get private key from PStoreCrypt singleton if we didn't supply
        # anything.
        if not private_key:
            private_key = PStoreCrypt.get().sshrsa_privkey
        # If something was supplied, make sure it already "parsed".
        elif isinstance(private_key, basestring):
            parser = sshrsa.SSHKeyParser()
            private_key = parser.parse_private(private_key)

        kwargs = dict((i, private_key[i]) for i in 'nedpq')
        crypt = sshrsa.RSACrypt(**kwargs)

        # NOTE: We're not doing tempfiles here.. the sshrsa encryption method
        # is currently limited to very few bytes anyway.
        if self.fp:
            data = self.fp.read()
        else:
            data = self.data

        decrypted = crypt.decrypt(data)
        return BytesIO(decrypted)


def decrypts(encrypted, type, private_key=None):
    """
    Decrypt ``encrypted`` (a ``str`` (byte string) instance containing
    encrypted data) to a bytestring.

    Encryption type ``type`` must be one of 'gpg' or 'sshrsa'.

    The ``private_key`` argument is optional. It's only needed for encryption
    types that have no built-in mechanism for selecting/serving the right
    private key; i.e. the sshrsa encryption type. The expected format is some
    kind of ascii armor.

    Called ``decrypts`` and not ``decrypt`` because of its similarity with
    ``pickle.loads()`` which also takes a byte string.

    Can raise a ``CryptError``.

    NOTE: This function is not used by pstore at the moment. But it exists to
    complement encrypts which is used.
    """
    obj = CryptoReader(data=encrypted, enctype=type)
    file = obj.decrypt_with(private_key)
    return file.read()


def encrypts(unencrypted, public_key):
    """
    Encrypt ``unencrypted`` (a ``str`` (byte string) instance) as a byte string
    using ``public_key`` as public key.

    The ``public_key`` must be a human readable public key of the GPG/PGP or
    public ssh key (sshrsa) type.

    Called ``encrypts`` and not ``encrypt`` because of its similarity with
    ``pickle.dumps()`` which also returns a byte string.
    """
    obj = CryptoWriter(data=unencrypted)
    file = obj.encrypt_with(public_key)
    return file.read()


if __name__ == '__main__':
    from base64 import b64decode
    from unittest import TestCase, main

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

        JOE_PUBKEY = ('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDOMBVBteGqm8VFRiP'
                      'NClGy8RLYf7etIg++qA6Xo7pThorzHU0LvXK0SDeUbTSgPUAfql8pD4'
                      'hATF89HzOUs5n6YHPvAu2MMXWGfaF5DMb+5f5JbfQLhIohfllmlwWig'
                      'HinteV6uhP7xNF/4MhEJgvGwa1AP5wESR+QHtefaZDsZQ== joe')

        JOE_PRIVKEY = ('''
            -----BEGIN RSA PRIVATE KEY-----
            MIICXAIBAAKBgQDOMBVBteGqm8VFRiPNClGy8RLYf7etIg++qA6Xo7pThorzHU0L
            vXK0SDeUbTSgPUAfql8pD4hATF89HzOUs5n6YHPvAu2MMXWGfaF5DMb+5f5JbfQL
            hIohfllmlwWigHinteV6uhP7xNF/4MhEJgvGwa1AP5wESR+QHtefaZDsZQIDAQAB
            AoGAVrN1XMpEeF9EFpsl1sRuEla42/zomY7nG/7DFBSu9wxuRUie6z7gitqLNIiv
            Rmo7GpWjqjpzysXSjnseT3suVY676FZXIk9dRzJ65OBUFEvuJqpg6tvlm4Gq3mMH
            RPhWRm7xDvzQs8aH0QwDeQYr5uamcXb+4tp7/2oD73eRS4ECQQD0otMhhAdLZ6Rt
            PkbskEGE+EgTiScoNI8eyXMAg4vdB0OhFa9HP+gMXhstF4h0+rK39IvCoIbieuZJ
            74tCvWaRAkEA18QJtTx6RE8u2m7oE8HMOTkcTnAerC61xeRWOYrDzGElT2Vf+GCM
            HpoUKd3VVYA1NwXv1bGfBCXmXKaXshGalQJBANg8qJUih/QeC5hIiRaHuHJZqBQk
            kokWVD+pX07f+BwKVLwpV8KJ+YodELZ9669C/gBeV79Ud4XvjmliJN18XxECQEla
            FBLRJJ/ka4FHAw70a4FosP7ZjxPqLVHBdq7JRhdNT2nWhPHjoL8mkoRJLiWLGIxE
            MGztnanDWLVWzWt0IKECQAnz52r6SQlbAVixBzf05eTBIYxk5RUbIv0v8eC8lusD
            F5Y0uvnipvQtzpgsOxiC8c5R0j40NKfQKCVq0aPM+Jw=
            -----END RSA PRIVATE KEY-----
        ''').strip()

        def setUp(self):
            PStoreCrypt.create(askpass=PStoreCrypt.ASKPASS_USERNAME2,
                               sshrsa_privkey_file=BytesIO(self.JOE_PRIVKEY))

        def tearDown(self):
            PStoreCrypt.destroy()

        def test_decrypts_gpg(self):
            input = ('hIwDpCCsUhak5FsBA/46Fi5ubNMPWRHAiPZdoWrazqhJfg9y9+vAK2'
                     'vheNWVkpjIXvCExwzgaTmSyghbkh1SI44gybNo0RoTD/a/HxIkxN+A'
                     'EcD1+XVYOhGjUcWeS8hOk1aSmlt0caaunLUphJuN2i0v5EnomxK3ZD'
                     'qM9EyXIIsVeQxWDeDYMKEaC0Yp+9JMAWC9489HCPjwwPuyhn3Xn1Lj'
                     'X2EWOL0pSIuYrBrDba3i56z7teTTMsc69qqta5k/52OAKHzR+Evh4E'
                     'lUlI/JSIptkz8GkXalBxFLuA==')
            input = b64decode(input)
            decrypted = decrypts(input, type='gpg')
            self.assertEquals(decrypted, 'mySuperSecret!')

        def test_encrypts_gpg(self):
            input = 'mySuperSecret!'
            encrypted = encrypts(input, self.ALEX_PUBKEY)
            self.assertNotEquals(encrypted, input)  # output changes at will

        def test_encrypts_decrypts_gpg(self):
            input = "is it john doe's birth day?"
            encrypted = encrypts(input, self.ALEX_PUBKEY)
            self.assertNotEquals(encrypted, input)  # output changes at will
            decrypted = decrypts(encrypted, type='gpg')
            self.assertEquals(decrypted, input)

        def test_decrypts_sshrsa(self):
            input = ('Y9bQbUMFQ0OGvBW/iQ0PDdMy5PmsJvsxONzLKjc6uyQ3yvkZHlH/V0'
                     'OQOAc/nnMpsJfnzeLv6oZfGzRffKrU90D712f2cvpnI4/FfSGI59HS'
                     '109Q9QilXAjMLqe06P6ceOI2HtxFw6/rIDCrY9/J75+MyHJBSAZ3uw'
                     'f/lKTx1xM=')
            input = b64decode(input)
            decrypted = decrypts(input, type='sshrsa')
            self.assertEquals(decrypted, 'mySuperSecret!')

        def test_encrypts_sshrsa(self):
            input = 'mySuperSecret!'
            encrypted = encrypts(input, self.JOE_PUBKEY)
            self.assertNotEquals(encrypted, input)  # output changes at will

        def test_encrypts_decrypts_sshrsa(self):
            input = "is it john doe's birth day?"
            encrypted = encrypts(input, self.JOE_PUBKEY)
            self.assertNotEquals(encrypted, input)  # output changes at will
            decrypted = decrypts(encrypted, type='sshrsa')
            self.assertEquals(decrypted, input)

        def test_cryptowriter_none(self):
            source = 'no encryption'
            # The writer should support writing multiple times.
            writer = CryptoWriter(data=source)
            self.assertEquals(writer.encrypt_with(None).read(), source)
            self.assertEquals(writer.encrypt_with(None).read(), source)
            writer = CryptoWriter(fp=BytesIO(source))
            self.assertEquals(writer.encrypt_with(None).read(), source)
            self.assertEquals(writer.encrypt_with(None).read(), source)

        def test_cryptoreader_none(self):
            source = 'no encryption'
            reader = CryptoReader(data=source, enctype='none')
            self.assertEquals(reader.decrypt_with(None).read(), source)
            reader = CryptoReader(fp=BytesIO(source), enctype='none')
            self.assertEquals(reader.decrypt_with(None).read(), source)

        def test_cryptoreader_gpg(self):
            source = 'gpg encrypted'
            encrypted = ('hIwDpCCsUhak5FsBA/9DeiA9hg+bQUGnkE4OeW1btR0SWr2Pt'
                         'sP5O8YgEh+ZcZRB/kQlHdaV580+bttXtmU3KE30d6KWMADWqI'
                         'hlLXR3Rk7ZswsgN59u8U2IaEuAR15M8rPS7dEFz4JT3Jic+zJ'
                         'QjJstPkiWxmkdndkP2cemWEXrXuIKXs/iY45DF+/iH9JLATnn'
                         'hGZOpDpya+3jFVMkEghaWwKnvrTQLElMwuyLEf49c5uY9khQF'
                         '3k49/hGTmRbzGqrEQm0zY220OISBqVkdiFUYNDI/EKeFVaw')
            encrypted = b64decode(encrypted)
            reader = CryptoReader(data=encrypted, enctype='gpg')
            self.assertEquals(reader.decrypt_with(None).read(), source)
            reader = CryptoReader(fp=BytesIO(encrypted), enctype='gpg')
            self.assertEquals(reader.decrypt_with(None).read(), source)

        def test_cryptoreader_sshrsa(self):
            source = 'sshrsa encrypted'
            encrypted = ('lTc467y3eLwlC2wy7TOgCOzzoo9OGq3DwbVCfCsHGRf'
                         'TmIElctu8a5uQvZ5+yAsTq2AvHYBZ3s4q3aM2tpNC0s'
                         'ophQ+XPziPkZBdV04Cof9rvYXKwSuuyqbKblOjOHsRc'
                         'KguppEfSWwUnZuMRxxgoJHfvR8GeHMFE0mngGF/uyc=')
            encrypted = b64decode(encrypted)
            reader = CryptoReader(data=encrypted, enctype='sshrsa')
            self.assertEquals(reader.decrypt_with(None).read(), source)
            reader = CryptoReader(fp=BytesIO(encrypted),
                                  enctype='sshrsa')
            self.assertEquals(reader.decrypt_with(None).read(), source)

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

            source = 'a bit of data'

            writer = CryptoWriter(fp=ReadOnce(source))
            fp1 = writer.encrypt_with(self.ALEX_PUBKEY)
            fp2 = writer.encrypt_with(self.JOE_PUBKEY)

            reader = CryptoReader(fp=fp1, enctype='gpg')
            decfp = reader.decrypt_with(None)
            self.assertEquals(decfp.read(), source)

            reader = CryptoReader(fp=fp2, enctype='sshrsa')
            decfp = reader.decrypt_with(self.JOE_PRIVKEY)
            self.assertEquals(decfp.read(), source)

    main()  # unittest.main
