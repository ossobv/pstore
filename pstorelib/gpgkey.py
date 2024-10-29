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
from warnings import warn

from pstorelib.pgpdump_tiny import AsciiData, BinaryData


__all__ = ('get_pubkey_id', 'get_pubkey_expiry')

# General order of packets:
# 6, (13, 2+)+, (14, 2+)+
TAG_PUBKEY = 6
TAG_USERID = 13
TAG_PUBSUBKEY = 14
TAG_SIGNATURE = 2


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
        if packet.raw == TAG_PUBKEY:
            return packet.key_id.decode('ascii')
    return None


def get_pubkey_expiry(data):
    generator = _get_packet_generator(data)
    creation = None
    key_id = None

    packet_expiry = []
    for packet in generator.packets():
        # If this is not a signature, it's something that can be signed.
        if packet.raw != TAG_SIGNATURE:
            packet_expiry.append(None)

        # The public key (main) packet.
        if packet.raw == TAG_PUBKEY:
            if key_id is not None:
                warn('Multiple keys in packet? Stopping')
                break

            creation = packet.creation_time
            key_id = packet.key_id

        # Signatures of packets, like userID or subkey. We're mostly interested
        # in the subkeys, but we'll match all.
        elif packet.raw == TAG_SIGNATURE:
            if packet.raw_key_expiration_time:
                expiry = packet.raw_key_expiration_time
                assert packet.key_id == key_id, (packet, packet.key_id, key_id)
                if packet_expiry[-1] is None:
                    packet_expiry[-1] = expiry
                else:
                    # Take the max because there might be an old signature left
                    # from the same signing master key.
                    packet_expiry[-1] = max(
                        packet.raw_key_expiration_time, expiry)

    # Did we get no expiry at all? Then this key has infinite lifetime.
    if all(exp is None for exp in packet_expiry):
        expiry = None

    # Otherwise we should have expiry values for all packets. Coalesce into
    # single value.
    else:
        assert len(packet_expiry) >= 2, packet_expiry
        if packet_expiry[0] is None:
            packet_expiry.pop(0)  # no signature for the master packet
        assert not any(exp is None for exp in packet_expiry), packet_expiry
        smallest_expiry = min(*packet_expiry)
        expiry = creation + timedelta(seconds=smallest_expiry)

    return expiry
