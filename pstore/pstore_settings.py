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

Example project settings. Use this if pstore is the only app in your
project.

DEFAULT_FROM_EMAIL, SERVER_EMAIL, MANAGERS, ADMINS DATABASES, SECRET_KEY
should be defined in your site settings.

"""
from logging import Filter
from logging.handlers import SysLogHandler

# We're in UTC+1, we speak English and we don't do any i18n.
TIME_ZONE, LANGUAGE_CODE = 'Europe/Amsterdam', 'en-us'
USE_I18N, USE_TZ = False, True

# Currently only used for admin-media, relative to STATIC_URL: /static/admin/
STATIC_URL = '/static/'

# Generally unused, but still needed.
SITE_ID = 1

# If you have 8 users and 13 properties, you'll exceed the default 100 files
# during the upload. Increase this by a lot.
DATA_UPLOAD_MAX_NUMBER_FILES = 2000

# Middleware.
MIDDLEWARE = [
    # #'pstore.middleware.LogSqlToConsoleMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',

    # Make sure we have a the requirements for admin work.
    'django.contrib.sessions.middleware.SessionMiddleware',     # sessions
    'django.contrib.auth.middleware.AuthenticationMiddleware',  # request.user
    'django.contrib.messages.middleware.MessageMiddleware',     # UI feedback

    # Authenticate users by nonce instead.
    'pstore.middleware.AuthenticateByNonceMiddleware',

    # Handle HttpErrors by feeding them as response.
    'pstore.middleware.HttpErrorMiddleware',
]

# Path to our pstore urls.
ROOT_URLCONF = 'pstore.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'pstore.wsgi.application'

# The apps that this project is comprised of.
INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.messages',
    'django.contrib.sessions',
    'django.contrib.staticfiles',
    'pstore',
)

TEMPLATES = (
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.request',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
)

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'  # use max 2^9 records


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
    'formatters': {
        'syslog': {
            'format': 'uwsgi[%(process)d]: %(name)s: %(message)s',
        },
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
            'formatter': 'syslog',
            'facility': SysLogHandler.LOG_AUTH,
        },
    },
    'loggers': {
        # Put INFO or worse in syslog.
        'pstore.audit': {
            'handlers': ('syslog',),
            'level': 'INFO',
            'propagate': True,
        },
        # Mail admins on ERROR or worse (not just for django.request).
        # And also write to the same auth.log, because it clarifies that
        # the previous statement didn't complete.
        '': {
            'handlers': ('syslog', 'mail_admins'),
            'level': 'ERROR',
            'propagate': True,
        },
    },
}
