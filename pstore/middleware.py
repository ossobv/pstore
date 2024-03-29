# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
django-pstore -- Python Protected Password Store (Django app)
Copyright (C) 2010,2012,2013,2015  Walter Doekes <wdoekes>, OSSO B.V.

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
import time

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.db import connection
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme

try:
    from kleides_dssoclient.middleware import DssoLoginMiddleware
except ImportError:
    DssoLoginMiddleware = None


from pstore.http import HttpError
from pstore.security import validate_nonce_b64


class AuthenticateByNonceMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.method == 'GET':
            nonce_b64 = request.GET.get('nonce_b64')
        elif request.method == 'POST':
            nonce_b64 = request.POST.get('nonce_b64')
        else:
            nonce_b64 = None

        if nonce_b64:
            nonce_b64 = nonce_b64.encode('ascii')
            assert not hasattr(request, '_cached_user')
            request.user = validate_nonce_b64(nonce_b64)
            request.user.used_nonce = True
        else:
            request.user.used_nonce = False

        return None


class HttpErrorMiddleware(MiddlewareMixin):
    def process_exception(self, request, exception):
        if isinstance(exception, HttpError):
            return HttpResponse(content=exception.user_description,
                                content_type='text/plain; charset=utf-8',
                                status=exception.status_code)
        return None


class LogSqlToConsoleMiddleware(MiddlewareMixin):
    """
    Log all SQL statements direct to the console (in debug mode only).
    Intended for use with the django development server.

    Insert as first element in MIDDLEWARE_CLASSES when you need it.

    http://www.djangosnippets.org/snippets/1672/ by davepeck, 6-aug-2009.
    """
    def process_request(self, request):
        self.t0 = time.time()
        return None

    def process_response(self, request, response):
        if (settings.DEBUG and connection.queries
                and (not settings.MEDIA_URL
                     or not request.META['PATH_INFO'].startswith(
                         settings.MEDIA_URL))
                and not request.META['PATH_INFO'].startswith('/jsi18n/')):
            print('\n' + '=' * 72)

            if 'time' in connection.queries[0]:
                total = sum(float(q['time']) for q in connection.queries)
                for i, query in enumerate(connection.queries):
                    print('>>> (%d) %ss: %s' % (
                        i, query['time'], query['sql']))
                print('== %d queries in %f seconds ==\n' % (
                    len(connection.queries), total))

            else:
                for i, query in enumerate(connection.queries):
                    print('>>> (%d): %s' % (i, query['sql']))
                print('== %d queries in %f seconds ==' % (
                    len(connection.queries), time.time() - self.t0))

        return response


if DssoLoginMiddleware:
    class PstoreDssoLoginMiddleware(DssoLoginMiddleware):
        def process_request(self, request):
            # Only initiate DSSO authentication when visiting the login url.
            if not request.path.startswith((
                    settings.LOGIN_URL, '/accounts/login/', '/login/')):
                return

            # Authenticate.
            response = super().process_request(request)

            if response is None and request.user.is_authenticated:
                # Perform redirect after login.
                next_url = request.POST.get(
                    REDIRECT_FIELD_NAME,
                    request.GET.get(REDIRECT_FIELD_NAME))
                if not url_has_allowed_host_and_scheme(
                        url=next_url, allowed_hosts={request.get_host()},
                        require_https=request.is_secure()):
                    next_url = '/'
                return redirect(next_url)

            return response
