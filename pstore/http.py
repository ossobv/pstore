# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
django-pstore -- Python Protected Password Store (Django app)
Copyright (C) 2012,2013,2015  Walter Doekes <wdoekes>, OSSO B.V.

    This application is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published
    by the Free Software Foundation; either version 3 of the License, or (at
    your option) any later version.

    This application is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this application; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307,
    USA.
"""
import logging

from django.core.servers.basehttp import FileWrapper
from django.http import HttpResponse

from pstorelib.bytes import get_size


logger = logging.getLogger('pstore')


class HttpError(Exception):
    """
    This exception is passed on to the HTTP layer where it is propagated back
    to the client.
    """
    def __init__(self, status_code, user_description, error_description=None):
        """
        The status_code is the HTTP error code.
        The user_description is the problem description returned over HTTP.
        Optionally error_description may hold a text that gets sent to the
        error log.
        """
        super(HttpError, self).__init__(status_code, user_description)
        self.status_code = status_code
        self.user_description = user_description

        if error_description:
            # Passing args instead of instance, as we'd otherwise lose the
            # error_description in the error mail.
            args = (status_code, user_description, error_description)
            sys_exc_info = (HttpError, args, None)
            logger.error(error_description, exc_info=sys_exc_info)


class EncryptedResponse(HttpResponse):
    """
    An HTTP response returning encrypted data. It doesn't do any encryption, it
    just adds the appropriate headers for the decrypting end to know how to
    decrypt it.
    """
    def __init__(self, data=None, fp=None, enctype=None):
        """
        Specify either file or data.
        """
        assert bool(data) ^ bool(fp)
        assert enctype in ('none', 'gpg', 'sshrsa')

        if data:
            assert isinstance(data, str)  # .. and not unicode
            content = data
            content_length = len(data)
        else:
            content = FileWrapper(fp)
            content_length = get_size(fp)
            assert content_length != -1

        ctype = 'application/octet-stream'
        super(EncryptedResponse, self).__init__(content, content_type=ctype)
        self['Content-Length'] = content_length
        self['X-Encryption'] = enctype


class VoidResponse(HttpResponse):
    """
    An HTTP response without any content.
    """
    def __init__(self):
        content = 'OK'
        ctype = 'text/plain; charset=us-ascii'

        # Status: 204 No Content
        super(VoidResponse, self).__init__(content_type=ctype,
                                           status=204)
        self['Content-Length'] = len(content)
