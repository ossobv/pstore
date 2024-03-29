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

from base64 import b64decode, b64encode
from codecs import getreader
from json import load as from_jsonfile
from random import randint
from socket import error as SocketError
from sys import exc_info, stderr
try:
    from urllib.error import HTTPError, URLError
    from urllib.parse import quote, unquote, urlencode
    from urllib.request import Request, urlopen
except ImportError:
    from urllib import quote, unquote, urlencode
    from urllib2 import HTTPError, Request, URLError, urlopen
from pstorelib.crypt import CryptoReader
from pstorelib.exceptions import (BackendDown, BackendError, NotAllowed,
                                  NotFound, NoNonce)

unicode = type(u'')
utf8_reader = getreader('utf-8')


class Backend(object):
    """
    Interface to the PStore backend. Uses HTTP(S) as transport protocol.
    """
    def __init__(self, urls, user, verbose=False):
        self.urls = urls
        self.user = user
        self.verbose = verbose

    def newnonce(self):
        path = '/nonce.bin'
        # Setting data to the empty tuple forces a POST operation.
        try:
            reader = self._communicate(path, data=(), query={'u': self.user})
        except NotAllowed:
            raise NoNonce()
        nonce = reader.decrypt_with().read()
        # Passing non-UTF-8 binary data in POST data is legit, but not
        # understood by Django. We could pass it as a file, or we can encode it
        # as base64. Choosing base64 because of the limited size of the nonce.
        # Now we won't have to invent "magic" file/property names for the
        # nonce.
        return b64encode(nonce).decode('ascii').rstrip('=')

    def propget(self, objectid, property):
        path = '/propget/%s/%s.bin' % (urlquote(objectid), urlquote(property))
        out = {u'nonce_b64': self.newnonce(), 'u': self.user}
        reader = self._communicate(path, query=out)
        return reader.decrypt_with(), reader.enctype

    def propset(self, objectid, property, files=None, o_excl=False):
        assert files

        path = '/propset/%s/%s.bin' % (urlquote(objectid), urlquote(property))
        out = {u'nonce_b64': self.newnonce()}
        if o_excl:  # "ensure new"
            out[u'o_excl'] = u'1'

        none = self._communicate(path, data=out, files=files)
        assert none is None

    def propupd(self, objectid, files=None):
        # FIXME: add: data = new user permissions
        assert files
        path = '/propupd/%s.bin' % (urlquote(objectid),)
        out = {u'nonce_b64': self.newnonce()}
        none = self._communicate(path, data=out, files=files)
        assert none is None

    def propsearch(self, allowed_only=True, propkey_icontains=None,
                   propvalue_icontains=None):
        path = '/propsearch.js'
        out = {u'nonce_b64': self.newnonce()}
        if allowed_only:
            out['u'] = self.user
        if propkey_icontains is not None:
            out['propkey_icontains'] = propkey_icontains
        if propvalue_icontains is not None:
            out['propvalue_icontains'] = propvalue_icontains

        data = self._communicate(path, query=out)
        for machine, properties in data.items():
            for propkey, info in properties['properties'].items():
                if info['data']:
                    info['data'] = CryptoReader(data=b64decode(info['data']),
                                                enctype=info['enctype'])
                else:
                    del info['data']

        return data

    def validate(self):
        path = '/validate.js'
        out = {u'nonce_b64': self.newnonce()}
        statusdata = self._communicate(path, query=out)
        return statusdata['errors']

    def _communicate(self, path, query=None, data=None, files=None):
        # urlencode is nice because it will accept boths dicts and lists of
        # tuples.
        query_string = ''
        if query:
            assert (isinstance(query, dict) or isinstance(query, list)
                    or isinstance(query, tuple))
            query_string = '?' + urlencode(query)

        if files:
            assert isinstance(files, list)
            form = MultiPartForm()
            if data:
                if (isinstance(data, list) or isinstance(data, tuple)):
                    iterator = data
                elif isinstance(data, dict):
                    iterator = data.items()
                else:
                    assert False
                # Note that you must send ASCII or UTF-8 encoded data here.
                # Otherwise the Django POST parser will mangle the data.
                # (Therefore the nonce is sent as base64 string.)
                for name, value in iterator:
                    # Only ascii strings here.
                    assert isinstance(name, unicode), name
                    assert isinstance(value, unicode), value
                    form.add_field(name.encode('ascii'), value.encode('ascii'))

            for name, filename, file in files:
                # Only bytestrings here.
                assert not isinstance(name, unicode), name
                assert not isinstance(filename, unicode), filename
                form.add_file(name, filename, file)  # no content-type..
            content_type = form.get_content_type()
            content_length = form.get_length()
            data = form.get_data()

        elif data is not None:
            assert (isinstance(data, dict) or isinstance(data, list)
                    or isinstance(data, tuple))
            content_type = 'application/x-www-form-urlencoded'
            data = urlencode(data).encode('ascii')
            content_length = len(data)

        else:
            content_type, content_length = None, None

        return self._try_servers(
            path, query_string, data, content_type, content_length)

    def _try_servers(self, path, query_string, data, content_type,
                     content_length):
        first_exception = None

        for store_url in self.urls:
            if self.verbose:
                stderr.write('- Communicating with %s%s\n' % (
                    store_url, path))

            try:
                response = self._try_server(
                    store_url, path, query_string, data, content_type,
                    content_length)

            except HTTPError as e:
                if not first_exception:
                    first_exception = exc_info()

                status_code = e.code
                try:
                    body = e.read().decode('utf-8', 'replace')
                finally:
                    e.close()
                if status_code == 403:
                    raise NotAllowed()
                elif status_code == 404:
                    raise NotFound()
                elif status_code < 500:
                    if len(body) > 1024:
                        body = body[0:1021] + '...'
                    raise BackendError(body)

            except (SocketError, URLError):
                if not first_exception:
                    first_exception = exc_info()

            else:
                break
        else:
            # Re-raise original exception: connection to all stores failed.
            first_url = self.urls[0]
            exception = BackendDown('could not connect to %s' % (first_url,))
            exception.__cause__ = first_exception[1]  # PEP 3134 style
            raise exception  # following form is not python3 compatible
            # raise exception, None, first_exception[2]  # pep complaint: W602

        return response

    def _try_server(self, store_url, path, query_string, data, content_type,
                    content_length):
        request = Request(str(store_url + path + query_string))
        if data is not None:
            request.add_header('Content-Type', content_type)
            request.add_header('Content-Length', content_length)
            try:
                request.add_data
            except AttributeError:
                request.data = data  # python3
            else:
                request.add_data(data)  # python2

        file = urlopen(request)
        status = file.getcode()
        assert status in (200, 204)  # OK, OK-no-data

        # Break early if we're dealing with no-data.
        if status == 204:
            try:
                nothing = file.read()
                assert len(nothing) == 0, nothing
            finally:
                file.close()
            data = None
            key_expiry = None

        # JSON data?
        elif path.endswith('.js'):
            try:
                data = from_jsonfile(utf8_reader(file))
            finally:
                file.close()
            key_expiry = None

        # Binary data?
        elif path.endswith('.bin'):
            # We expect this to be set!
            try:
                file.headers.getheader
            except AttributeError:  # py3
                content_length = file.headers.get('content-length')
                enctype = file.headers.get('x-encryption', 'none')
                key_expiry = file.headers.get('x-key-expiry')
            else:  # py2
                content_length = file.headers.getheader('content-length')
                enctype = file.headers.getheader('x-encryption', 'none')
                key_expiry = file.headers.getheader('x-key-expiry')
            finally:
                length = int(content_length)
            # No file closing here.. the cryptoreader gets to use it.
            data = CryptoReader(fp=file, length=length, enctype=enctype)

        # Unknown data?
        else:
            file.close()
            raise NotImplementedError(path)

        # Show warning about keys about to expire.
        if key_expiry and (int(key_expiry) // 86400) < 90:
            stderr.write(
                'WARNING: your (sub)key will expire in %.1f days\n\n' % (
                    float(key_expiry) / 86400.0))

        return data

    ###########################################################################
    # UTILITY
    ###########################################################################

    def get_keys(self, users):
        path = '/users.js'
        out = [(u'nonce_b64', self.newnonce())] + [('q', i) for i in users]
        userdata = self._communicate(path, query=out)
        if set(users) != set(userdata.keys()):
            raise NotFound('did not receive same list of users: '
                           'got only "%s"; do the others exist?' %
                           (', '.join(userdata.keys()),))

        # Reduce dictionary to a set of keys.
        ret = {}
        for key, value in userdata.items():
            ret[str(key)] = str(value['key'])
        return ret

    def get_object(self, objectid, allowed_only=True):
        path = '/object/%s.js' % (urlquote(objectid),)
        out = {u'nonce_b64': self.newnonce()}
        if allowed_only:
            out['u'] = self.user.encode('ascii')
        objdata = self._communicate(path, query=out)

        # The public and shared properties are b64encoded because of the JSON
        # transport. Undo that. And add the appropriate decryption routines.
        for property, info in objdata['properties'].items():
            if info['data'] is None:
                continue

            # We're not calling decrypt_with() on it directly. The caller may
            # not want it decrypted, so we'll save us some cpu.
            info['data'] = CryptoReader(data=b64decode(info['data']),
                                        enctype=info['enctype'])

        return objdata

    def get_objects(self, objectid_contains=None, allowed_only=True,
                    verbose=False):
        nonce = self.newnonce()  # all operations require a nonce
        out = {u'nonce_b64': nonce}
        if objectid_contains:
            out['q'] = objectid_contains  # e.g. a partial object name
        if allowed_only:
            out['u'] = self.user
        if verbose:
            out['v'] = '1'  # list more than just the object identifier

        path = '/objects.js'
        return self._communicate(path, query=out)


# def post_multipart(host, selector, fields, files):
#     content_type, body = encode_multipart_formdata(fields, files)
#     h = httplib.HTTP(host)
#     h.putrequest('POST', selector)
#     h.putheader('content-type', content_type)
#     h.putheader('content-length', str(len(body)))
#     h.endheaders()
#     h.send(body)
#     errcode, errmsg, headers = h.getreply()
#     return h.file.read()


class MultiPartForm(object):
    """
    Accumulate the data to be used when posting a form.

    Taken from: http://www.doughellmann.com/PyMOTW/urllib2/#uploading-files
    """
    BOUNDARY_IN = 'abcdefghijklmnopqrstuvwxyz0123456789'

    def __init__(self):
        self.form_fields = []
        self.files = []

        # Choose random boundary so that if an upload fails, it might succeed
        # on a second attempt.
        boundary = [self.BOUNDARY_IN[randint(0, len(self.BOUNDARY_IN) - 1)]
                    for i in range(48)]
        self.boundary = '--' + ''.join(boundary)

    def get_content_type(self):
        return 'multipart/form-data; boundary=%s' % self.boundary

    def add_field(self, name, value):
        """
        Add a simple field to the form data.
        """
        self.form_fields.append((name, value))

    def add_file(self, name, filename, file,
                 content_type='application/octet-stream'):
        """
        Add a file to be uploaded.
        """
        # NOTE: the name is the "field name"
        # FIXME: In the future we should be able to not read the entire file
        # body at this point.
        body = file.read()
        self.files.append((name, filename, content_type, body))

    def get_data(self):
        """
        Return a binstring representing the form data, including
        attached files.
        """
        if not hasattr(self, '_data'):
            # Build a list of lists, each containing "lines" of the request.
            # Each part is separated by a boundary string. Once the list is
            # built, return a string where each line is separated by '\r\n'.
            parts = []
            part_boundary = b'--' + self.boundary.encode('ascii')

            # Add the form fields.
            for name, value in self.form_fields:
                parts.extend([
                    part_boundary,
                    b'Content-Disposition: form-data; name="%s"' % (name,),
                    b'',
                    value,
                ])

            # Add the files to upload.
            for name, filename, content_type, body in self.files:
                parts.extend([
                    part_boundary,
                    b'Content-Disposition: file; name="%s"; filename="%s"' % (
                        name, filename),
                    b'Content-Type: %s' % (content_type.encode('ascii'),),
                    b'',
                    body,
                ])

            # Flatten the list and add closing boundary marker, then return
            # CR+LF separated data.
            parts.extend([part_boundary + b'--', b''])
            self._data = b'\r\n'.join(parts)

        return self._data

    def get_length(self):
        return len(self.get_data())


def urlquote(param):
    """
    Encodes parameters for use in a path. That means that slashes get
    encoded as %2F. But then, we replace the percent sign with equals
    signs. Because of the following issue:

    http://lists.unbit.it/pipermail/uwsgi/2011-March/001621.html
    > CGI spec says that PATH_INFO should be decoded
    > WSGI says nothing, but as it does not mention REQUEST_URI as a
    > standard variable we could have no way to determine (after
    > decoding) if a / was a / or a %2F.
    """
    # Safe '' means that there are very few characters that do not get
    # escaped.
    if isinstance(param, unicode):
        param = param.encode('utf-8')
    return quote(param, safe='').replace('%', '=')


def urlunquote(param):
    """
    Undo the doings of urlquote.
    """
    param = unquote(param.replace('=', '%'))
    if isinstance(param, unicode):
        param = param.encode('latin1')  # unquote did not parse utf8
    return param.decode('utf-8')


if __name__ == '__main__':
    stderr.write('FIXME: unittest for {0}\n'.format(__file__))
