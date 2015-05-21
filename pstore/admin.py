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
from django.contrib import admin
from django.contrib.auth.models import User

from pstore.models import Object, ObjectPerm, Property, PublicKey

try:
    # Django 1.4+
    from django.contrib.admin import SimpleListFilter
except ImportError:
    # Django 1.3-
    ObjectUserFilter = None
else:
    class ObjectUserFilter(SimpleListFilter):
        title = 'user'
        parameter_name = 'user'  # used in url

        def lookups(self, request, model_admin):
            """
            Returns elements for query filter on the side. Usernames are added
            both with and without a plus, where the former one means: "select
            only records that match *only* that user".
            """
            users = []
            for user in (User.objects.order_by('-is_active', 'username')
                         .only('id', 'username')):
                users.append((user.id, user.username))
                users.append(('%d+' % (user.id,), '%s+' % (user.username,)))
            return users

        def queryset(self, request, queryset):
            value = self.value()
            if not value:
                return queryset

            # If the value ends with a '+', the user must be in the allowed
            # list.
            if value.endswith('+'):
                value = value[0:-1]
                match_only = False
            # If it doesn't, the user must be the only one in the allowed list.
            else:
                match_only = True

            queryset = queryset.filter(allowed__user__id=value)
            if match_only:
                # Filter by records that have only one allowed user.
                queryset = queryset.extra(
                    where=[('(SELECT COUNT(*) FROM pstore_objectperm '
                            'WHERE object_id = pstore_object.id) = 1')]
                )

            return queryset


class ObjectAdmin(admin.ModelAdmin):
    def users(self, object):
        all = [i.user.username + ('', '*')[i.can_write]
               for i in (ObjectPerm.objects.filter(object=object)
                         .select_related('user'))]
        return ', '.join(sorted(all))

    list_display = ('identifier', 'users')
    ordering = ('identifier',)
    search_fields = ('identifier',)

    if ObjectUserFilter:
        list_filter = (ObjectUserFilter,)


class ObjectPermAdmin(admin.ModelAdmin):
    list_display = ('object', 'user', 'can_write')


class PropertyAdmin(admin.ModelAdmin):
    def short_value(self, object):
        if (object.type & object.BIT_ENCRYPTED):
            return '(encrypted)'

        value = object.value[0:32]
        if len(value) >= 32:
            value = value + '...'
        return repr(value)  # makes sure we won't see non-ascii

    exclude = ('value',)  # raw/binary values.. should not be in admin
    list_display = ('id', 'object', 'name', 'short_value', 'user')
    ordering = ('object__identifier', 'name', 'user__username')
    search_fields = ('object__identifier', 'name')


class PublicKeyAdmin(admin.ModelAdmin):
    list_display = ('__unicode__', 'description')
    ordering = ('user__username',)


admin.site.register(Object, ObjectAdmin)
admin.site.register(ObjectPerm, ObjectPermAdmin)
admin.site.register(Property, PropertyAdmin)
admin.site.register(PublicKey, PublicKeyAdmin)
