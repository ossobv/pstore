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
from functools import wraps
from logging import getLogger

from django.utils.decorators import available_attrs


logger = getLogger('pstore.audit')


def audit_view(description, takes_user=True, mutates=False):
    """
    Decorator to log the calling of this view.  Usage::

        @require_POST_nonce
        @audit_view('bakes pizza', mutates=True)
        def baking_pizza_view(request, user):
            # ...
    """
    if takes_user:
        def decorator(func):
            @wraps(func, assigned=available_attrs(func))
            def inner(request, user, *args, **kwargs):
                humanargs = ', '.join(list(args) +
                                      ['%s=%s' % (k, v)
                                       for k, v in kwargs.items()])
                address = str(request.META.get('REMOTE_ADDR', 'UNKNOWN_IP'))
                message = (u'User %s on %s %s %s' %
                           (user.username, address, description, humanargs))

                if mutates:
                    # Use 'warning' as there is no 'notice' level. And encode
                    # as UTF-8 because the automatic encoding would add a BOM
                    # before the message. See:
                    # http://serverfault.com/questions/407643/
                    #       rsyslog-update-on-amazon-linux-suddenly-treats-
                    #       info-level-messages-as-emerg
                    logger.warning(message.encode('utf-8'))
                else:
                    logger.info(message.encode('utf-8'))

                return func(request, user, *args, **kwargs)
            return inner

    else:
        def decorator(func):
            @wraps(func, assigned=available_attrs(func))
            def inner(request, *args, **kwargs):
                humanargs = ', '.join(list(args) +
                                      ['%s=%s' % (k, v)
                                       for k, v in kwargs.items()])
                address = str(request.META.get('REMOTE_ADDR', 'UNKNOWN_IP'))
                message = (u'User %s on %s %s %s' %
                           ('UNKNOWN_USER', address, description, humanargs))

                if mutates:
                    logger.warning(message.encode('utf-8'))
                else:
                    logger.info(message.encode('utf-8'))

                return func(request, *args, **kwargs)
            return inner

    return decorator
