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
from django.contrib import admin
from django.views.generic.base import RedirectView

try:
    # Django 1.4+
    from django.conf.urls import include, patterns
except ImportError:
    # Django 1.3-
    from django.conf.urls.defaults import include, patterns


admin.autodiscover()


urlpatterns = patterns('pstore',  # noqa
    # Object identifiers and property names may need to be escaped to allow for
    # the slash (/).

    ###########################################################################
    # JSON interface, for smaller items of data.
    ###########################################################################

    # Get verbose info about a single object.
    (r'^object/(?P<object_identifier>[^/]+).js$',
     'views_js.get_object'),
    # Get a (partial) listing of objects.
    (r'^objects.js$',
     'views_js.list_objects'),
    # Get a (partial) listing of users.
    (r'^users.js$',
     'views_js.list_users'),

    # Get DB consistency report.
    (r'^validate.js$',
     'views_js.validate'),

    ###########################################################################
    # Binary interface, for properties (which can be large)
    ###########################################################################

    # Get a new nonce.
    (r'^nonce.bin$',
     'views_bin.create_nonce'),

    # Get a single object property.
    (r'^propget/(?P<object_identifier>[^/]+)/(?P<property_name>[^/]+).bin$',
     'views_bin.get_property'),
    # Create object and/or set property.
    (r'^propset/(?P<object_identifier>[^/]+)/(?P<property_name>[^/]+).bin$',
     'views_bin.set_property'),

    # Update all shared (encrypted) properties at once. Used when
    # adding/revoking user permissions. (TODO: create a separate one, usable
    # for revoking only? OR: allow update to specify the "bogus" file so that
    # it keeps the original for that user.)
    (r'^propupd/(?P<object_identifier>[^/]+).bin$',
     'views_bin.update_properties'),

    # Search for properties.
    (r'^propsearch.js$',
     'views_js.search_properties'),

    ###########################################################################
    # Admin interface
    ###########################################################################

    # Use / as the admin path (only if this is the only app in the project)
    # (point people to the right url.. fails to work if STATIC_URL is '/')
    (r'^admin(/.*)$', RedirectView.as_view(url='/', permanent=False)),
    (r'', include(admin.site.urls)),
)
