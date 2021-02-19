# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
django-pstore -- Python Protected Password Store (Django app)
Copyright (C) 2012,2013,2015,2018  Walter Doekes <wdoekes>, OSSO B.V.

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
from django.core.exceptions import ValidationError
from django.test import TestCase

# The Property has a "name" property which is an AsciiField and a "value"
# property which is a BlobField. We test both here.
from pstore.models import Object, Property


class FieldTest(TestCase):

    def test_create(self):
        obj = Object.objects.create(identifier='test-server')
        with self.assertRaises(ValidationError):
            Property.objects.create(object=obj, name='unicode-\u20ac')

    def test_binary(self):
        binary = b'\x00\x01\x02...abc...\xfd\xfe\xff'

        obj = Object.objects.create(identifier='test-server')
        prop = Property.objects.create(object=obj, name='binary', value=binary)
        prop_id = prop.id
        del prop

        # Lookup and compare
        prop2 = Property.objects.get(id=prop_id)
        self.assertTrue(isinstance(prop2.value, (bytes, memoryview)))
        self.assertEqual(bytes(prop2.value), binary)

    def test_lowascii(self):
        # Test control characters and check that no one does CRLF replacing.
        binary = bytearray(range(0, 32)) + b'\r\n\r\n'

        obj = Object.objects.create(identifier='test-server')
        prop = Property.objects.create(object=obj, name='lowascii',
                                       value=binary)
        prop_id = prop.id
        del prop

        # Lookup and compare
        prop2 = Property.objects.get(id=prop_id)
        self.assertTrue(isinstance(prop2.value, (bytes, memoryview)))
        self.assertEqual(bytes(prop2.value), binary)

    def test_long(self):
        data512 = ((b'A' * 127 + b'\n') + (b'B' * 127 + b'\n')
                   + (b'C' * 127 + b'\n') + (b'C' * 127 + b'\n'))
        data = (4096 * (2 * data512)) + b'..tail'  # 4MB and a little
        self.assertEqual(len(data), 4096 * 1024 + 6)

        obj = Object.objects.create(identifier='test-server')
        prop = Property.objects.create(object=obj, name='long', value=data)
        prop_id = prop.id
        del prop

        # Lookup and compare
        prop2 = Property.objects.get(id=prop_id)
        self.assertTrue(isinstance(prop2.value, (bytes, memoryview)))
        self.assertEqual(bytes(prop2.value), data)
