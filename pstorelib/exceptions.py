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


class PStoreException(Exception):
    class_ = 'general error'

    def __init__(self, *args, **kwargs):
        super(Exception, self).__init__(*args, **kwargs)
        if self.args or not self.description:
            self.args = tuple((self.class_,) + self.args)
        else:
            self.args = (self.class_, self.description)


class BackendError(PStoreException):
    class_ = 'backend error'
    description = 'undefined'


class BackendDown(BackendError):
    description = 'backend is down/unreachable'


class CryptError(PStoreException):
    class_ = 'crypto error'
    description = 'undefined'


class CryptBadPassword(CryptError):
    description = 'insufficient typing skills detected'


class CryptBadPubKey(CryptError):
    description = 'missing or invalid public key'


class CryptBadPrivKey(CryptError):
    description = 'missing or invalid private key'


class UserError(PStoreException):
    class_ = 'user error'
    description = 'undefined'


class NotAllowed(UserError):
    description = 'lookup denied (no permission or not found)'


class NotFound(UserError):
    description = 'lookup failed (not found)'


class NoNonce(UserError):
    description = ('nonce creation refused '
                   '(wrong user? too many unused nonces?)')
