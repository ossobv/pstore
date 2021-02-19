# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
django-pstore -- Python Protected Password Store (Django app)
Copyright (C) 2017,2018  Walter Doekes <wdoekes>, OSSO B.V.

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
from decimal import Decimal
from optparse import make_option

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db.models import Count

from pstore.models import Object, ObjectPerm, Property

# Numeric types
NUMERIC_TYPES = (float, int, Decimal)


class Command(BaseCommand):
    help = __doc__ = """
        Make a two dimensional CSV export of objects and properties.

        Lists all objects in the DB, with all users and whether they
        have access. Also lists the most common properties and their
        values.
    """.replace('\n        ', '\n').strip()

    option_list = BaseCommand.option_list + (
        make_option(
            '--with-encrypted', action='store_true', default=False, help=(
                'Also list encrypted properties (without value obviously)')),
        make_option(
            '--common-if-gte', action='store', type=int,
            default=8, metavar='N', help=(
                'Properties are considered common if used by at least N '
                'objects (greater than or equal)')),
    )

    def handle(self, **kwargs):
        self.show_encrypted = kwargs['with_encrypted']
        self.min_properties = kwargs['common_if_gte']

        self.stdout.write(self.get_head_row())
        for obj in Object.objects.order_by('identifier'):
            self.stdout.write(self.get_row(obj))

    def to_row(self, iterable):
        return ';'.join(iterable) + '\n'

    def to_column(self, value):
        if isinstance(value, NUMERIC_TYPES):
            return str(value)
        elif value == '':
            return ''
        else:
            return '"' + str(value).replace('"', '""') + '"'

    def get_head_row(self):
        return self.to_row(self.get_headers())

    def get_row(self, obj):
        return self.to_row(
            self.get_columns_for_object(obj)
            + tuple(('', 'x')[i]
                    for i in self.get_columns_for_usernames(obj))
            + self.get_columns_for_properties(obj))

    def get_columns_for_object(self, obj):
        return (self.to_column(obj.pk), self.to_column(obj.identifier))

    def get_columns_for_usernames(self, obj):
        allowed = (
            ObjectPerm.objects.filter(object=obj)
            .values_list('user', flat=True).distinct())
        map_ = self.get_usernames_to_ids()
        return tuple(
            map_[username] in allowed
            for username in self.get_usernames())

    def get_columns_for_properties(self, obj):
        names = self.get_property_names()

        pub_properties = dict(
            obj.properties.filter(name__in=names)
            .filter(type=Property.TYPE_PUBLIC)
            .values_list('name', 'value'))

        shared_properties = (
            obj.properties.filter(name__in=names)
            .filter(type=Property.TYPE_SHARED)
            .values_list('name', flat=True).distinct())
        shared_properties = dict(
            (i, '<enc>') for i in shared_properties)

        properties = pub_properties
        properties.update(shared_properties)

        return tuple(self.to_column(properties.get(i, '')) for i in names)

    def get_headers(self):
        if not hasattr(self, '_get_headers'):
            self._get_headers = (
                ('oid', 'object',)
                + tuple('U:' + i for i in self.get_usernames())
                + tuple('P:' + i for i in self.get_property_names()))
        return self._get_headers

    def get_usernames(self):
        if not hasattr(self, '_get_usernames'):
            self._get_usernames = tuple(
                User.objects.values_list('username', flat=True)
                .order_by('username'))
        return self._get_usernames

    def get_usernames_to_ids(self):
        if not hasattr(self, '_get_usernames_to_ids'):
            self._get_usernames_to_ids = dict(
                User.objects.values_list('username', 'id'))
        return self._get_usernames_to_ids

    def get_property_names(self):
        if not hasattr(self, '_get_property_names'):
            qs = (
                Property.objects.values_list('name', flat=True)
                .annotate(Count('object', distinct=True))
                .filter(object__count__gte=self.min_properties)
                .order_by('-object__count', 'name'))
            if not self.show_encrypted:
                qs = qs.filter(type=Property.TYPE_PUBLIC)
            self._get_property_names = tuple(qs)
        return self._get_property_names
