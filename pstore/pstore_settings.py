# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
django-pstore -- Python Protected Password Store (Django app)
Copyright (C) 2010,2012,2013  Walter Doekes <wdoekes>, OSSO B.V.

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

Example project settings. Use this if pstore is the only app in your
project.

DEFAULT_FROM_EMAIL, SERVER_EMAIL, MANAGERS, ADMINS DATABASES, SECRET_KEY
should be defined in your site settings.

"""
# We're in UTC+1, we speak English and we don't do any i18n.
TIME_ZONE, LANGUAGE_CODE = 'Europe/Amsterdam', 'en-us'
USE_I18N, USE_L10N, USE_TZ = False, False, False

# Currently only used for admin-media, relative to STATIC_URL: /static/admin/
STATIC_URL = '/static/'

# Generally unused, but still needed.
SITE_ID = 1

# Middleware.
MIDDLEWARE_CLASSES = (
    #'pstore.middleware.LogSqlToConsoleMiddleware',

    #DJANGO1.4+#'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.common.CommonMiddleware',

    # Makes sure we have a session for admin work.
    'django.contrib.sessions.middleware.SessionMiddleware',
    # Attaches user to the request object.
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    # The admin interface needs this for feedback.
    'django.contrib.messages.middleware.MessageMiddleware',

    # We want operations to be atomic!
    'django.middleware.transaction.TransactionMiddleware',
)

# Path to our pstore urls.
ROOT_URLCONF = 'pstore.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'pstore.wsgi.application'

# The apps that this project is comprised of.
INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'pstore',
)

# Logging.
from logging import Filter
from logging.handlers import SysLogHandler


# (extra LF above for PEP)
class RequireDebugFalse(Filter):
    """For compatibility with Django 1.3-"""
    def filter(self, record):
        from django.conf import settings
        return not settings.DEBUG

LOGGING = {
    # NOTE: If you are getting log messages printed to stdout/stderr, you're
    # probably looking at a python 2.6- bug where syslog messages are encoded
    # as UTF-8 with a BOM. The BOM is read as EMERG and the message is "wall"ed
    # to all logged in users.
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'require_debug_false': {
            # In Django 1.4+ we'd use django.utils.log.RequireDebugFalse.
            '()': RequireDebugFalse,
        }
    },
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'filters': ('require_debug_false',),  # don't mail if DEBUG=False
            'class': 'django.utils.log.AdminEmailHandler',
        },
        'syslog': {
            'level': 'INFO',
            'class': 'logging.handlers.SysLogHandler',
            'address': '/dev/log',  # don't forget this for sysloghandler
            'facility': SysLogHandler.LOG_AUTH,
        },
    },
    'loggers': {
        # Mail admins on ERROR or worse.
        'django.request': {
            'handlers': ('mail_admins',),
            'level': 'ERROR',
            'propagate': True,
        },
        # Put INFO or worse in syslog.
        'pstore.audit': {
            'handlers': ('syslog',),
            'level': 'INFO',
            'propagate': True,
        },
    },
}
