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
from django.conf import settings
from django.http import HttpResponse
from django.utils.encoding import force_unicode
from django.utils.functional import Promise
from django.utils.simplejson import JSONEncoder, dumps


class _JsonEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Promise):
            return force_unicode(obj)
        return obj


class JsonResponse(HttpResponse):
    """
    Output response as json.
    """
    def __init__(self, request, json_response):
        if not isinstance(json_response, basestring):
            json_kwargs = {
                'check_circular': False,
                'cls': _JsonEncoder,
                'ensure_ascii': False,
                'indent': 2,
                'sort_keys': True,
            }
            if not settings.DEBUG:
                json_kwargs.update({'indent': None, 'separators': (',', ':')})
            json_response = dumps(json_response, **json_kwargs)
        super(JsonResponse, self).__init__(json_response,
                                           content_type='application/json')
