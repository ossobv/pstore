# vim: set ts=8 sw=4 sts=4 et ai tw=79 syn=python:
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

Example WSGI config for django-pstore project.

This module contains the WSGI application used by Django's development server
and any production WSGI deployments. It should expose a module-level variable
named ``application``. Django's ``runserver`` and ``runfcgi`` commands discover
this application via the ``WSGI_APPLICATION`` setting.

Usually you will have the standard Django WSGI application here, but it also
might make sense to replace the whole Django WSGI application with a custom one
that later delegates to the Django one. For example, you could introduce WSGI
middleware here, or combine a Django application with an application of another
framework.

"""
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pstore.settings')

###############################################################################
# If you're using virtualenv(1) to manage your python dependencies, you
# can set the sys.path from your project virtualenv here:
# #import sys
# #sys.path[:] = [/* different path list */]
# But your wsgi server might be in the know about virtualenv. E.g. for uwsgi
# you can do this in the config:
# #virtualenv = /srv/virtualenvs/pstore
# Possibly combined with the PYTHONPATH environment variable:
# #env = PYTHONPATH=/srv/django-apps:/opt/django14
###############################################################################

# This application object is used by any WSGI server configured to use this
# file. This includes Django's development server, if the WSGI_APPLICATION
# setting points here.
try:
    from django.core.wsgi import get_wsgi_application
except ImportError:  # django1.3- ?
    from django.core.handlers.wsgi import WSGIHandler as get_wsgi_application
application = get_wsgi_application()
