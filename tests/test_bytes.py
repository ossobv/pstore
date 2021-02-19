# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore-lib -- Python Protected Password Store (Library)
Copyright (C) 2012,2013,2015,2018  Walter Doekes <wdoekes>, OSSO B.V.

    This library is free software; you can redistribute it and/or modify it
    under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or (at
    your option) any later version.

    This library is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307,
    USA.
"""

from io import BytesIO
import os
from sys import stdin
from tempfile import TemporaryFile
from unittest import TestCase

from pstorelib.bytes import FileWithoutTrailingEnter, can_seek, get_size


class Test(TestCase):
    def test_can_seek_bytesio(self):
        self.assertTrue(can_seek(BytesIO()))

    def test_can_seek_file(self):
        with TemporaryFile() as t:
            self.assertTrue(can_seek(t))

    def test_can_seek_stdin(self):
        self.assertFalse(can_seek(stdin))

    def test_get_size_bytesio(self):
        self.assertEqual(get_size(BytesIO(b'12345')), 5)

    def test_get_size_file(self):
        with TemporaryFile() as t:
            t.write(b'12345')
            self.assertEqual(get_size(t), 5)
            t.write(b'1')
            self.assertEqual(get_size(t), 6)

    def test_get_size_stdin(self):
        self.assertEqual(get_size(stdin), -1)


class TestFileWithoutTrailingEnter(TestCase):
    def create_child(self):
        rp, wp = os.pipe()

        childpid = os.fork()
        if not childpid:
            os.close(rp)
            self.wf = os.fdopen(wp, 'wb')
            return True

        os.close(wp)
        self.rf = os.fdopen(rp, 'rb')
        self.childpid = childpid
        return False

    def teardown_child(self):
        self.wf.close()
        os._exit(0)

    def teardown_parent(self):
        self.rf.close()
        os.waitpid(self.childpid, 0)

    def test_selftest(self):
        if self.create_child():
            self.wf.write(b'test\n')
            self.wf.flush()
            self.teardown_child()
        else:
            self.assertEqual(self.rf.read(5), b'test\n')
            self.teardown_parent()

    def test_trailing_nolf(self):
        if self.create_child():
            self.wf.write(b'ABC\nDEF')
            self.teardown_child()
        else:
            wrapped = FileWithoutTrailingEnter(self.rf)
            self.assertEqual(wrapped.read(4), b'ABC\n')
            self.assertEqual(wrapped.read(-1), b'DEF')
            self.teardown_parent()

    def test_trailing_nolf2(self):
        if self.create_child():
            self.wf.write(b'ABC\nDEF')
            self.teardown_child()
        else:
            wrapped = FileWithoutTrailingEnter(self.rf)
            self.assertEqual(wrapped.read(4), b'ABC\n')
            self.assertEqual(wrapped.read(3), b'DEF')
            self.assertEqual(wrapped.read(2), b'')
            self.teardown_parent()

    def test_trailing_1lf(self):
        if self.create_child():
            self.wf.write(b'ABC\nDEF\n')
            self.teardown_child()
        else:
            wrapped = FileWithoutTrailingEnter(self.rf)
            self.assertEqual(wrapped.read(4), b'ABC\n')
            self.assertEqual(wrapped.read(-1), b'DEF')
            self.teardown_parent()

    def test_trailing_2crlf(self):
        if self.create_child():
            self.wf.write(b'ABC\n\r\n\r\n')
            self.teardown_child()
        else:
            wrapped = FileWithoutTrailingEnter(self.rf)
            self.assertEqual(wrapped.read(32), b'ABC\n\r\n')
            self.teardown_parent()

    def test_trailing_2lf(self):
        if self.create_child():
            self.wf.write(b'ABC')
            self.wf.flush()
            self.wf.write(b'DEF\n')
            self.wf.flush()
            self.wf.write(b'\n\n')
            self.wf.flush()
            self.teardown_child()
        else:
            wrapped = FileWithoutTrailingEnter(self.rf)
            self.assertEqual(wrapped.read(4), b'ABCD')
            self.assertEqual(wrapped.read(3), b'EF\n')
            self.assertEqual(wrapped.read(2), b'\n')
            self.teardown_parent()
