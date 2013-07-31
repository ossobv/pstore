# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore-lib -- Python Protected Password Store (Library)
Copyright (C) 2012,2013  Walter Doekes <wdoekes>, OSSO B.V.

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
try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO


__all__ = ('BytesIO', 'sendfile')


BytesIO  # touching it to make it look used


def can_seek(fp):
    """
    Some file-like objects do have a seek attribute but raise an Illegal Seek
    IOError on usage.
    """
    try:
        fp.seek(0, 1)  # SEEK_CUR, move 0 bytes forward/backward
    except:  # AttributeError, IOError
        return False
    return True


def get_size(fp):
    """
    Getting the size of a file-like object is sometimes possible. If it isn't,
    return -1.
    """
    if hasattr(fp, 'size'):
        size = fp.size()
    elif hasattr(fp, 'getvalue'):
        size = len(fp.getvalue())
    elif can_seek(fp):
        pos = fp.tell()
        fp.seek(0, 2)       # SEEK_END
        size = fp.tell()
        fp.seek(pos, 0)     # SEEK_SET
    else:
        size = -1
    return size


def sendfile(outfp, infp):
    """
    Transfer data between file objects.

    Similar to linux sendfile(2) which takes file descriptors and a few extra
    arguments. Returns the number of bytes written.

    At http://code.google.com/p/pysendfile there is a project which uses the
    actual syscall. But we won't be needing that.
    """
    bytes = 0
    bufsize = 65536

    while True:
        chunk = infp.read(bufsize)
        chunk_len = len(chunk)
        outfp.write(chunk)
        bytes += chunk_len
        if chunk_len != bufsize:
            break  # EOF

    return bytes


if __name__ == '__main__':
    from sys import stdin
    from tempfile import TemporaryFile
    from unittest import TestCase, main

    class Test(TestCase):
        def test_can_seek_bytesio(self):
            self.assertTrue(can_seek(BytesIO()))

        def test_can_seek_file(self):
            with TemporaryFile() as t:
                self.assertTrue(can_seek(t))

        def test_can_seek_stdin(self):
            self.assertFalse(can_seek(stdin))

        def test_get_size_bytesio(self):
            self.assertEquals(get_size(BytesIO('12345')), 5)

        def test_get_size_file(self):
            with TemporaryFile() as t:
                t.write('12345')
                self.assertEquals(get_size(t), 5)
                t.write('1')
                self.assertEquals(get_size(t), 6)

        def test_get_size_stdin(self):
            self.assertEquals(get_size(stdin), -1)

    main()  # unittest.main()
