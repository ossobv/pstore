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

import os
import re
import sys
from getpass import getpass
from sys import stderr
from time import time

try:
    from gpgme import ERR_CANCELED, Context, GpgmeError
except ImportError, e:
    raise ImportError(e.args[0] + '\n\n*HINT* apt-get install python-gpgme')

from pstorelib.bytes import BytesIO
from pstorelib.exceptions import (CryptError, CryptBadPassword,
                                  CryptBadPubKey, CryptBadPrivKey)
from pstorelib.gpgkey import get_pubkey_id_from_ascii


# A few notes about subkeys:
#
# -----------------------------------------------------------------------------
# From: http://wiki.debian.org/subkeys
#
# > GnuPG actually uses a signing-only key as the master key, and creates an
# > encryption subkey automatically. Without a subkey for encryption, you
# > can't have encrypted e-mails with GnuPG at all. Debian requires you to
# > have the encryption subkey so that certain kinds of things can be e-mailed
# > to you safely, such as the initial password for your debian.org shell
# > account.
# ...
# > You should keep your private master key very, very safe. However, keeping
# > all your keys extremely safe is inconvenient: every time you need to sign
# > a new package upload, you need to copy the packages onto suitable portable
# > media, go into your sub-basement, prove to the armed guards that you're
# > you by using several methods of biometric and other identification, go
# > through a deadly maze, feed the guard dogs the right kind of meat, and
# > then finally open the safe, get out the signing laptop, and sign they
# > packages. Then do the reverse to get back up to your Internet connection
# > for uploading the packages.
# >
# > Subkeys make this easier: you create a subkey for signing, and another for
# > encryption, and keep those on your main computer. You publish the subkeys
# > on the normal keyservers, and everyone else will use them instead of the
# > master keys, with one exception. Likewise, you will use the master keys
# > only in exceptional circumstances.
#
# -----------------------------------------------------------------------------
# From: http://serverfault.com/questions/397973/
#              gpg-why-am-i-encrypting-with-subkey-instead-of-primary-key
#
# > If you look into the details of the math of public-key encryption, you will
# > discover that signing and decrypting are actually identical operations.
# > Thus in a naive implementation it is possible to trick somebody into
# > decrypting a message by asking them to sign it.
# >
# > Several things are done in practice to guard against this. The most obvious
# > is that you never sign an actual message, instead you sign a secure hash of
# > the message. Less obviously, but just to be extra safe, you use different
# > keys for signing and encrypting.
#
# -----------------------------------------------------------------------------
# From: http://lavica.fesb.hr/cgi-bin/info2html?(gpgme)Key%20Management
#
# > The first subkey in the linked list is also called the primary key.
#
# -----------------------------------------------------------------------------
# The Key object that we get below, generally holds two subkeys:
# >>> [(i.can_sign, i.can_encrypt, i.pubkey_algo) for i in k.subkeys]
# [(True, False, 17), (False, True, 16)]
#
# (Where 17 is PUBKEY_ALGO_DSA and 16 is PUBKEY_ALGO_ELGAMAL_E.)


# Not so nice, security-wise. But without password-caching the thing becomes
# unusable now that we require the nonce for reading too.
PASSWORD_CACHE = {}


class GPGCrypt(object):
    """
    Wrapper around GPGME GPG encrypting/decrypting.
    """
    def __init__(self):
        # Gnome keyring already takes care of the key access if you're running
        # X. If you cancel the GPG popup, you get this callback instead.
        self.password_cb = self.default_password_cb
        # Init a GPG context.
        self.context = Context()
        self.context.passphrase_cb = self._password_cb  # wrap the other cb
        # No ascii armor stuff. We'll juggle some base64 around ourselves.
        self.context.armor = False

    def set_password_cb(self, password_cb):
        # Set password callback. The callback must return a (password,
        # allow_caching) tuple.
        self.password_cb = password_cb

    def generate_key(self, **kwargs):
        # <GnupgKeyParms format="internal">
        # (Sub)Key-Type: RSA
        # (Sub)Key-Length: 2048 (or 4096)
        # Name+Comment+Email "Alex Boonstra (TEST) <aboonstra@example.com>"
        # Expire-Date: None (or in a couple of years)
        # Passphrase: xxx
        # |
        # v
        # self.context.op_genkey(parms.encode('utf-8'), None, None)
        # result = self.context.op_genkey(parms.encode('utf-8'), None, None)
        msg = ('This takes too long. Generate they keys yourself. Look in '
               'docs/examples for an example')
        raise NotImplementedError(msg)

    def get_key(self, **kwargs):
        """
        Get the appropriate key to work with.

        Takes either an id= or an email= argument.

        TODO: if the key is not found, get it from server?
        """
        if (len(kwargs) != 1 or
                any(i not in ('id', 'email') for i in kwargs.keys())):
            raise TypeError('get_key takes either id= or email=')

        # Lookup by id.
        if 'id' in kwargs:
            # "If [PARAM2] is 1, only private keys will be returned."
            key = self.context.get_key(kwargs['id'], 0)
            # Make sure we have an e-mail to go by.
            email = unicode(key.uids[0].email.lower())

        # Lookup by email. E-mail returned by gpgme is in unicode. (Even
        # though it probably won't contain any non-ascii.)
        else:
            email = unicode(kwargs['email']).lower()
            found = []

            for key in self.context.keylist():
                for uid in key.uids:
                    if uid.email.lower() == email:
                        found.append(key)
                        if len(found) > 1:
                            msg = 'Cannot cope with more than one recipient'
                            raise NotImplementedError(msg)
            if not found:
                return None

            key = found[0]

        # Do checks on the key.
        if key.expired:
            raise CryptBadPubKey('%s key is expired' % (email,))
        elif key.invalid or key.revoked or key.disabled:
            raise CryptBadPubKey('%s key is invalid/revoked/diabled' %
                                 (email,))
        elif not key.can_encrypt:  # also set to false if e.g. expired
            raise CryptBadPubKey('%s key is unusable' % (email,))

        # Find right subkey and check if expiry is nigh.
        for subkey in key.subkeys:
            if not (subkey.expired or subkey.invalid or subkey.revoked or
                    subkey.disabled or not subkey.can_encrypt):
                break
        if subkey.expires and float(subkey.expires - time()) / 86400.0 < 200:
            # Send out a warning that this key is about to expires. I'm not
            # sure what the implications of expired keys are, but let's prepare
            # for the worst and warn the user at an early stage.
            print >>stderr, \
                ('WARNING: (sub)key %s for %s will expire in '
                 '%.1f days' %
                 (subkey.keyid, key.uids[0].email,
                  float(subkey.expires - time()) / 86400.0))

        # Ok. All is good.
        return key

    def import_key(self, key):
        to_import = BytesIO(str(key))  # ensure bytestring!
        res = self.context.import_(to_import)
        if (res.imported + res.unchanged) != 1:
            raise CryptError('import failed (imported=%d, unchanged=%d). '
                             'Try setting os.environ["GNUPGHOME"] to an '
                             '*existing* writable path in settings; '
                             'e.g. "/tmp"' % (res.imported, res.unchanged))

        try:
            key_id = get_pubkey_id_from_ascii(key)
            key = self.get_key(id=unicode(key_id))
        except Exception, e:
            raise CryptError('GPG quick hack failed; no key found', e)

        return key

    def decrypt(self, private_key_ref=None, input=None, output=None):
        """
        Can raise one of the CryptErrors.
        """
        assert private_key_ref is None, 'We let the keyring handle this'
        assert hasattr(input, 'read')
        assert hasattr(output, 'write')

        try:
            self.context.decrypt(input, output)
        except GpgmeError, e:
            # If you press ^C during passphrase input.
            #   gpgme.GpgmeError: (7, 58, u'No data')
            # If the decryption failed (badly encrypted, secret key missing)
            #   gpgme.GpgmeError: (7, 152, u'Decryption failed')
            # If the password callback raised an error.
            #   gpgme.GpgmeError: (7, 32779, u'Bad file descriptor')
            if e.args[0] == 7:
                if e.args[1] == 11:
                    raise CryptBadPassword()
                if e.args[1] == 152:
                    raise CryptBadPrivKey()
            raise

        # length = output.tell()
        output.seek(0)

    def encrypt(self, public_key_ref=None, input=None, output=None):
        """
        We're always encrypting to a single user at a time. That makes revoking
        user permissions easier: we don't have to re-encrypt the whole bunch.
        """
        assert public_key_ref is not None
        assert hasattr(input, 'read')
        assert hasattr(output, 'write')

        self.context.encrypt([public_key_ref], 1, input, output)

        # length = output.tell()
        output.seek(0)

    def default_password_cb(self, id_name_comment_email, key_ids,
                            prev_was_bad):
        email = re.search(r'<([^@>]+@[^>]+)>', id_name_comment_email)
        if email:
            email = email.groups()[0]
        else:
            email = '(unknown)'
        return (getpass('Enter passphrase for %s GPG key: ' % (email,)),
                True)  # allow caching

    def _password_cb(self, id_name_comment_email, key_ids, prev_was_bad, fd):
        # Password caching.
        password, allow_caching = None, False
        if id_name_comment_email in PASSWORD_CACHE:
            if prev_was_bad:
                del PASSWORD_CACHE[id_name_comment_email]
            else:
                password = PASSWORD_CACHE[id_name_comment_email]
                print >>sys.stderr, 'NOTICE: re-using cached password'

        # Get the password from the callback.
        try:
            if not password:
                password, allow_caching = self.password_cb(
                    id_name_comment_email, key_ids, bool(prev_was_bad)
                )
        except KeyboardInterrupt:
            # For some reason, we return 'No data' next..
            pass
        except Exception:
            import traceback
            traceback.print_exc()
        else:
            if password and allow_caching:
                PASSWORD_CACHE[id_name_comment_email] = password
            # Writing empty passwords too, because the close below is so
            # drastic that we wouldn't get a second try.
            assert isinstance(password, str), 'password was unicode?'
            os.write(fd, password + '\n')
            return 0

        # > The user must write the passphrase, followed by a newline
        # > character, to the file descriptor fd. If the user returns 0
        # > indicating success, the user must at least write a newline
        # > character before returning from the callback.
        # >
        # > If an error occurs, return the corresponding gpgme_error_t value.
        # > You can use the error code GPG_ERR_CANCELED to abort the operation.
        # > Otherwise, return 0.
        #
        # But that doesn't work. We must always write a newline, or the thing
        # hangs. Returning 0 or ERR_CANCELED doesn't seem to make any
        # difference. So, instead, we close() the fd. That will make for a
        # quicker abort: 'Bad file descriptor'
        os.close(fd)
        return ERR_CANCELED


if __name__ == '__main__':
    import unittest

    class Test(unittest.TestCase):
        KEY_ALEX = ('ECCF8511CA3F91BBD9BD09FEC797D1A5DD9DB7EB',
                    'alex@example.com')
        KEY_WALTER = ('ED3DB90502DE8DB34510544E66E99FD00350A01C',
                      'walter@example.com')

        def password_callback(self, id_name_comment_email, key_ids,
                              prev_was_bad):
            first_name = id_name_comment_email.rsplit('<', 1)[1]
            first_name = first_name.split('@', 1)[0]
            return (first_name + '2', False)  # (password, allow_caching)

        def test_1(self):
            g = GPGCrypt()
            g.set_password_cb(self.password_callback)

            source = 'sEcReT!'

            # FIXME/TODO: charge the GPGCrypt with the respective pgp public
            # and private keys before attempting any of this..

            recipients = (self.KEY_ALEX, self.KEY_WALTER)

            for recipient in recipients:
                key = g.get_key(id=recipient[0])

                input = BytesIO(source)
                output = BytesIO()
                g.encrypt(input=input, output=output, public_key_ref=key)
                encrypted = output.read()

                # Valid assumption when input is small.
                self.assertTrue(len(encrypted) > len(source))

                # Decrypt it
                input = BytesIO(encrypted)
                output = BytesIO()
                g.decrypt(input=input, output=output)
                decrypted = output.read()

                self.assertEquals(decrypted, source)

        # FIXME: cover more with the unit tests

    unittest.main()
