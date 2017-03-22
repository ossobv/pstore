from decimal import Decimal

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db.models import Count

from pstore.models import Object, ObjectPerm, Property

# Numeric types
try:
    long
except NameError:
    NUMERIC_TYPES = (float, int, Decimal)
else:
    NUMERIC_TYPES = (float, int, long, Decimal)
# Unicode type
try:
    unicode
except NameError:
    unistr = str
else:
    unistr = unicode

# List both public and private properties.
SHOW_ENCRYPTED = True
# List all common properties for which at least N objects exist with
# that property.
MIN_PROPERTIES = 8


class Command(BaseCommand):
    def handle(self, **kwargs):
        self.stdout.write(self.get_head_row())
        for obj in Object.objects.order_by('identifier'):
            self.stdout.write(self.get_row(obj))

    def to_row(self, iterable):
        return u';'.join(iterable) + '\n'

    def to_column(self, value):
        if isinstance(value, NUMERIC_TYPES):
            return unistr(value)
        elif value == u'':
            return u''
        else:
            return u'"' + unistr(value).replace(u'"', u'""') + u'"'

    def get_head_row(self):
        return self.to_row(self.get_headers())

    def get_row(self, obj):
        return self.to_row(
            self.get_columns_for_object(obj) +
            tuple((u'', u'x')[i]
                  for i in self.get_columns_for_usernames(obj)) +
            self.get_columns_for_properties(obj))

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
            (i, u'<enc>') for i in shared_properties)

        properties = pub_properties
        properties.update(shared_properties)

        return tuple(self.to_column(properties.get(i, u'')) for i in names)

    def get_headers(self):
        if not hasattr(self, '_get_headers'):
            self._get_headers = (
                (u'oid', u'object',) +
                tuple(u'U:' + i for i in self.get_usernames()) +
                tuple(u'P:' + i for i in self.get_property_names()))
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
                .filter(object__count__gte=MIN_PROPERTIES)
                .order_by('-object__count', 'name'))
            if not SHOW_ENCRYPTED:
                qs = qs.filter(type=Property.TYPE_PUBLIC)
            self._get_property_names = tuple(qs)
        return self._get_property_names
