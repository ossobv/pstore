# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore-lib -- Python Protected Password Store (Library)
Copyright (C) 2013,2015,2017,2018,2024  Walter Doekes <wdoekes>, OSSO B.V.

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
from datetime import timedelta

from pstorelib.pgpdump_tiny import AsciiData, BinaryData


__all__ = ('get_pubkey_id', 'get_pubkey_expiry')


def _get_packet_generator(data):
    if isinstance(data, str) and data.lstrip().startswith('-----BEGIN PGP '):
        generator = AsciiData(data)  # from string
    elif data and isinstance(data[0], int) and data.lstrip().startswith(
            b'-----BEGIN PGP '):
        generator = AsciiData(data)  # from binstring
    else:
        generator = BinaryData(data)
    return generator


def get_pubkey_id(data):
    generator = _get_packet_generator(data)
    for packet in generator.packets():
        if packet.raw == 6:
            return packet.key_id.decode('ascii')
    return None


def get_pubkey_expiry(data):
    generator = _get_packet_generator(data)
    creation = None
    expiry = None

    for packet in generator.packets():
        if packet.raw == 2:
            if packet.raw_key_expiration_time:
                if expiry is not None:
                    expiry = min(packet.raw_key_expiration_time, expiry)
                else:
                    expiry = packet.raw_key_expiration_time
        elif packet.raw == 6:
            creation = packet.creation_time

    if expiry:
        assert creation, 'creation not set??'
        expiry = creation + timedelta(seconds=expiry)

    return expiry
