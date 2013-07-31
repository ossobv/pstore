# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
django-pstore -- Python Protected Password Store (Django app)
Copyright (C) 2012,2013  Walter Doekes <wdoekes>, OSSO B.V.

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
from base64 import b64decode
from functools import wraps

from django.utils.decorators import available_attrs
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404

from pstore.models import Nonce


def get_object_or_403(*args, **kwargs):
    """
    Act as get_object_or_404 but raise PermissionDenied when not found. We
    don't want needless disclosure.
    """
    try:
        result = get_object_or_404(*args, **kwargs)
    except Http404:
        raise PermissionDenied()
    return result


def require_GET_nonce(func):
    """
    Decorator to make a view only accept GET requests with a nonce_b64
    argument.  Usage::

        @require_GET_nonce
        def my_view(request, user):
            # I can assume now that only GET requests make it this far
            # and they've got an authenticated user too
            # ...
    """
    @wraps(func, assigned=available_attrs(func))
    def inner(request, *args, **kwargs):
        if request.method != 'GET':
            return HttpResponseNotAllowed()
        user = validate_nonce_b64(request.GET.get('nonce_b64'))
        return func(request, user, *args, **kwargs)
    return inner


def require_POST_nonce(func):
    """
    Decorator to make a view only accept POST requests with a nonce_b64
    argument.  Usage::

        @require_POST_nonce
        def my_view(request, user):
            # I can assume now that only POST requests make it this far
            # and they've got an authenticated user too
            # ...
    """
    @wraps(func, assigned=available_attrs(func))
    def inner(request, *args, **kwargs):
        if request.method != 'POST':
            return HttpResponseNotAllowed()
        user = validate_nonce_b64(request.POST.get('nonce_b64'))
        return func(request, user, *args, **kwargs)
    return inner


def validate_nonce_b64(nonce_b64):
    """
    Decode the nonce_b64 and find a matching validated user.
    """
    if not Nonce.is_sane_b64(nonce_b64):
        raise PermissionDenied('Is not a nonce')

    # Re-add padding.
    nonce_b64 += (2 - ((len(nonce_b64) + 2) % 3)) * '='
    try:
        nonce = b64decode(nonce_b64)
    except TypeError:
        raise PermissionDenied('Nonce decoding failed')

    try:
        nonce = Nonce.objects.select_related('user').get(value=nonce)
    except Nonce.DoesNotExist:
        raise PermissionDenied('Nonce not found')
    else:
        if nonce.is_expired():
            raise PermissionDenied('Nonce expired')

    # Who are you?
    user = nonce.user

    # Is this user valid?
    if not user.is_active:
        raise PermissionDenied('Nonce for inactive user')

    # Ok the user is validated. Delete the nonce to make sure it's not
    # reusable.
    nonce.delete()

    return user
