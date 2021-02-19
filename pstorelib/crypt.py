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
from io import BytesIO, UnsupportedOperation
from os import fdopen
# TODO: make a SecureSpooledTemporaryFile that cleans up better after itself?
from tempfile import SpooledTemporaryFile

from pstorelib.bytes import can_seek, get_size, sendfile
from pstorelib.gpg import GPGCrypt, Data as GPGData


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

    def __init__(self, askpass=None):
        self.askpass = askpass or self.ASKPASS_DEFAULT


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
        gpgcrypt = GPGCrypt()
        gpgkey = gpgcrypt.import_key(public_key)

        if self.fp:
            input = self.fp
        else:
            input = GPGData(self.data)
        if self.use_tempfile:
            output = SpooledTemporaryFile(MAX_INMEMORY_SIZE)
        else:
            output = GPGData()

        gpgcrypt.encrypt(input=input, output=output, public_key_ref=gpgkey)

        if self.use_tempfile:
            return output
        return BytesIO(output.read())


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

        assert enctype in ('none', 'gpg')
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

    def decrypt_with(self):
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
            return self._decrypt_with_none()
        elif enctype == 'gpg':
            return self._decrypt_with_gpg()
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
        gpgcrypt = GPGCrypt()

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
