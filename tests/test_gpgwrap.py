# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore-lib -- Python Protected Password Store (Library)
Copyright (C) 2012,2013,2015-2016,2018  Walter Doekes <wdoekes>, OSSO B.V.

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
from unittest import TestCase

from pstorelib.gpgwrap import Data, GPGCrypt


class Test(TestCase):
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

        source = b'sEcReT!'

        # FIXME/TODO: charge the GPGCrypt with the respective pgp public
        # and private keys before attempting any of this..

        recipients = (self.KEY_ALEX, self.KEY_WALTER)

        for recipient in recipients:
            key = g.get_key(id=recipient[0])

            input = Data(source)
            output = Data()
            g.encrypt(input=input, output=output, public_key_refs=[key])
            encrypted = output.read()

            # Valid assumption when input is small.
            self.assertTrue(len(encrypted) > len(source))

            # Decrypt it
            input = Data(encrypted)
            output = Data()
            g.decrypt(input=input, output=output)
            decrypted = output.read()

            self.assertEqual(decrypted, source)
