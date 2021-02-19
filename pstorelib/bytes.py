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

__all__ = ('FileWithoutTrailingEnter', 'can_seek', 'get_size', 'sendfile')


def can_seek(fp):
    """
    Some file-like objects do have a seek attribute but raise an Illegal Seek
    IOError on usage.
    """
    try:
        fp.seek(0, 1)  # SEEK_CUR, move 0 bytes forward/backward
    except Exception:  # AttributeError, IOError
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


class FileWithoutTrailingEnter(object):
    """
    If you're inputting a file over stdin, you can consider trimming
    the trailing EOF. This file wrapper does that.
    """
    def __init__(self, fp):
        self.fp = fp
        self.buf = b''
        self.eof = False

    def read(self, size=-1):
        if size == -1:
            readsize = size
        else:
            readsize = size - len(self.buf) + 2  # read more bytes

        # More bytes are needed
        if not self.eof and (size == -1 or readsize > 0):
            data = self.fp.read(readsize)
            if size != -1 and len(data) < readsize:
                self.eof = True
            if data:
                self.buf = self.buf + data

        # No bytes to keep? Return quickly.
        if not self.buf.endswith(b'\n'):
            if size == -1:
                ret, self.buf = self.buf, ''
            else:
                ret, self.buf = self.buf[0:size], self.buf[size:]
            return ret

        # Ok, hold back one or two bytes.
        if self.buf.endswith(b'\r\n'):
            keep = 2
        else:
            keep = 1

        if size == -1:
            ret, self.buf = self.buf[0:-keep], self.buf[-keep:]
        elif size <= len(self.buf) - keep:
            ret, self.buf = self.buf[0:size], self.buf[size:]
        else:
            assert self.eof
            ret, self.buf = self.buf[0:-keep], self.buf[-keep:]

        return ret
