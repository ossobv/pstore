# vim: set syn=python ts=8 sw=4 sts=4 et ai tw=79:
"""
django-pstore -- Python Protected Password Store (Django app)
Copyright (C) 2010,2012,2013,2015,2016  Walter Doekes <wdoekes>, OSSO B.V.

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
from pstore.pstore_settings import *  # noqa

import os
import pwd
import sys

_OSUSER = pwd.getpwuid(os.getuid())[0]

# Debugging
DEBUG = SCRIPT_DEBUG = TEMPLATE_DEBUG = True

# Set fully qualified source e-mail, otherwise some mailservers might reject
# mails.
DEFAULT_FROM_EMAIL = SERVER_EMAIL = 'Pstore <noreply@example.com>'

# E-mail settings
ADMINS = MANAGERS = (('Developers', '%s@example.com' % _OSUSER),)

# Path settings
STATIC_ROOT = '/srv/http/pstore/static'

# DB settings
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('POSTGRESQL_DB', '%s_pstore' % _OSUSER),
        'USER': os.environ.get('POSTGRESQL_USER', _OSUSER),
        'PASSWORD': os.environ.get('POSTGRESQL_PASSWORD', ''),
        'HOST': os.environ.get('POSTGRESQL_HOST', ''),
        'PORT': '',
        'ATOMIC_REQUESTS': True,
    },
}

# GnuPG requires a writable home.
# #import os
# #os.environ["GNUPGHOME"] = '/tmp'

if DEBUG:
    # While we're developing, it's nice to see backtraces on stderr. Especially
    # when we're calling the django project from our pstore application instead
    # of from a browser.
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': True,
        'formatters': {
            'simple': {'format': '[%(asctime)s] %(levelname)s %(name)s: '
                       '%(message)s', 'datefmt': '%d/%b/%Y %H:%M:%S'},
        },
        'handlers': {
            'console': {'level': 'DEBUG', 'class': 'logging.StreamHandler',
                        'formatter': 'simple'},
        },
        'loggers': {
            'django': {'handlers': ('console',), 'level': 'INFO'},
            'pstore': {'handlers': ('console',), 'level': 'INFO'},
        },
    }

# Secret key
SECRET_KEY = 'postgres'
