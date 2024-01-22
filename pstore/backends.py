# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
django-pstore -- Python Protected Password Store (Django app)
Copyright (C) 2023  Walter Doekes <wdoekes>, OSSO B.V.

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

from django.contrib.auth.backends import get_user_model

try:
    from kleides_dssoclient.backends import DssoLoginBackend
except ImportError:
    DssoLoginBackend = None

log = logging.getLogger(__name__)


if DssoLoginBackend:
    class PstoreDssoLoginBackend(DssoLoginBackend):
        create_unknown_user = False

        def authenticate(self, request=None, dsso_mapping=None):
            '''
            Custom backend that checks email instead of username,
            requires superuser privs and does not create users.
            '''
            if not dsso_mapping:
                return
            if not dsso_mapping.get('email'):
                return
            # Only allow superusers.
            # if dsso_mapping.get('is_superuser') not in ('True', 'true', '1'):
            #     return

            user = None
            email = dsso_mapping['email']
            UserModel = get_user_model()

            try:
                user = UserModel.objects.get(email=email)
            except UserModel.MultipleObjectsReturned:
                log.error(
                    'Authentication with email=%r returned multiple users: %r',
                    email, UserModel.objects.filter(email=email))
            except UserModel.DoesNotExist:
                pass

            return user
