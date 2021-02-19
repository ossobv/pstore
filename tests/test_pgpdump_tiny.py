# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
pstore-lib -- Python Protected Password Store (Library)
Copyright (C) 2013,2015,2017,2018  Walter Doekes <wdoekes>, OSSO B.V.

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

The code herein is mostly taken from python-pgpdump by DanMcGee, which in turn
is derived from 'pgpdump' by Kazuhiko Yamamoto.

https://pypi.python.org/pypi/pgpdump/1.3
http://www.mew.org/~kazu/proj/pgpdump/

It is trimmed down to only return the PGP key id.
"""
from base64 import b64decode
from unittest import TestCase

from pstorelib.pgpdump_tiny import AsciiData, BinaryData


class UnitTest(TestCase):
    HARM_PUBKEY_ASCII = '\n'.join((
        '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: GnuPG v1.4.11 (GNU/Linux)',
        '',
        'mI0EULkrqAEEANNAbAZvH13iidylQmrm3EC1zCj8gm3gWsqK/0a8qKD9sDpjRX/c',
        'zbBzYdd5f1yzw2O1U9rAcnAFbAeBzsAcw2iDLVcnM6HP1F7Hyz1phR7IssmW4unw',
        'JYY75WIWjIvSK3gFcZMQNXWlfANs1nwZ+Z6UxaJDvPR7lPIb3ibUeLufABEBAAG0',
        'JUhhcm0gR2VlcnRzIChURVNUKSA8aGFybUBleGFtcGxlLmNvbT6IuAQTAQIAIgUC',
        'ULkrqAIbLwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQt8MvZ2DlzsAD4AP/',
        'Tbu6Sc7IhmrlRdAN90BnxKNJDU9l8uWLGJ8dsli3pZ6NohdNubYgcwi5zBi3Cj8E',
        's0vYh8HBxkDPtAUI7vRyhAEw2Chwi1TWlOFEerpl5dNyxoHSDX2TQclnAkUw8KRv',
        'NLujHCK6p4mEjeBOZdn0r/Fs6YHkdN1y1VysnM3rr0C4jQRQuSuoAQQA0/RU/Er7',
        'ksyDndEcYOHOb6eBRGrbe+kIrbMWBRhgVN+FyAih+Zu9hACMFFof3OM2MVkQN8St',
        'vihPzryRZV7HVVJp0LplpzkUGDu5C4iTp1fGKsBZ23F1zfZyETEpMPYCWnKQeNzh',
        'VD6W7FBnSF5jVWy+Ro5oFc7w2cy7mibh0UUAEQEAAYkBPQQYAQIACQUCULkrqAIb',
        'LgCoCRC3wy9nYOXOwJ0gBBkBAgAGBQJQuSuoAAoJEN0HDbSvN/v/K2QD/3IW4Kxd',
        'bOgENnz+ov+aTRO948ooVxy7afdNK5lz41L9596rUSKJr2WFLaqlAQMf7KZTcv+V',
        'O9o+5UIHP5nOU8b2u0zV/FGdCIDSfc18iKOZmVmyCZCgG/JX01ZcianNPDMxu5tF',
        'ITbM+pPleA2LgAjOkRZhmX/ry7WZMNXGjNF0Y7UD/0reXaSJqA+gI0QoXSOYw5Sl',
        'LVs8T2Z40qp7FXhqf91OyhT/bwZHys9BudYZQzwA5a7a/NhyDmZFEk5FdCO7f6wl',
        'xy+EzYGZSKSPl9c0nHaL+ITKb+H65XmJbbxZ1AvzqqQH6k+0dUyJTzZn1qVLYYPP',
        'TeO36hkKrU3I+IJdE+GN',
        '=pxFX',
        '-----END PGP PUBLIC KEY BLOCK-----',
    ))

    HARM_PUBKEY_BINARY = b64decode(
        'mI0EULkrqAEEANNAbAZvH13iidylQmrm3EC1zCj8gm3gWsqK/0a8qKD9sDpjRX/c'
        'zbBzYdd5f1yzw2O1U9rAcnAFbAeBzsAcw2iDLVcnM6HP1F7Hyz1phR7IssmW4unw'
        'JYY75WIWjIvSK3gFcZMQNXWlfANs1nwZ+Z6UxaJDvPR7lPIb3ibUeLufABEBAAG0'
        'JUhhcm0gR2VlcnRzIChURVNUKSA8aGFybUBleGFtcGxlLmNvbT6IuAQTAQIAIgUC'
        'ULkrqAIbLwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQt8MvZ2DlzsAD4AP/'
        'Tbu6Sc7IhmrlRdAN90BnxKNJDU9l8uWLGJ8dsli3pZ6NohdNubYgcwi5zBi3Cj8E'
        's0vYh8HBxkDPtAUI7vRyhAEw2Chwi1TWlOFEerpl5dNyxoHSDX2TQclnAkUw8KRv'
        'NLujHCK6p4mEjeBOZdn0r/Fs6YHkdN1y1VysnM3rr0C4jQRQuSuoAQQA0/RU/Er7'
        'ksyDndEcYOHOb6eBRGrbe+kIrbMWBRhgVN+FyAih+Zu9hACMFFof3OM2MVkQN8St'
        'vihPzryRZV7HVVJp0LplpzkUGDu5C4iTp1fGKsBZ23F1zfZyETEpMPYCWnKQeNzh'
        'VD6W7FBnSF5jVWy+Ro5oFc7w2cy7mibh0UUAEQEAAYkBPQQYAQIACQUCULkrqAIb'
        'LgCoCRC3wy9nYOXOwJ0gBBkBAgAGBQJQuSuoAAoJEN0HDbSvN/v/K2QD/3IW4Kxd'
        'bOgENnz+ov+aTRO948ooVxy7afdNK5lz41L9596rUSKJr2WFLaqlAQMf7KZTcv+V'
        'O9o+5UIHP5nOU8b2u0zV/FGdCIDSfc18iKOZmVmyCZCgG/JX01ZcianNPDMxu5tF'
        'ITbM+pPleA2LgAjOkRZhmX/ry7WZMNXGjNF0Y7UD/0reXaSJqA+gI0QoXSOYw5Sl'
        'LVs8T2Z40qp7FXhqf91OyhT/bwZHys9BudYZQzwA5a7a/NhyDmZFEk5FdCO7f6wl'
        'xy+EzYGZSKSPl9c0nHaL+ITKb+H65XmJbbxZ1AvzqqQH6k+0dUyJTzZn1qVLYYPP'
        'TeO36hkKrU3I+IJdE+GN'
    )

    def get_pubkey_id_from_(self, data, class_):
        object = class_(data)
        for packet in object.packets():
            if packet.raw == 6:
                return packet.key_id.decode('ascii')

    def test_get_pubkey_id_from_ascii(self):
        value = self.get_pubkey_id_from_(self.HARM_PUBKEY_ASCII,
                                         class_=AsciiData)
        self.assertEqual(value, 'B7C32F6760E5CEC0')

    def test_get_pubkey_id_from_binary(self):
        value = self.get_pubkey_id_from_(self.HARM_PUBKEY_BINARY,
                                         class_=BinaryData)
        self.assertEqual(value, 'B7C32F6760E5CEC0')

    def test_get_pubkey_id_from_upstream_ascii(self):
        try:
            from pgpdump import AsciiData as UpstreamAsciiData
        except ImportError:
            pass
        else:
            value = self.get_pubkey_id_from_(self.HARM_PUBKEY_ASCII,
                                             class_=UpstreamAsciiData)
            self.assertEqual(value, 'B7C32F6760E5CEC0')

    def test_get_pubkey_id_from_upstream_binary(self):
        try:
            from pgpdump import BinaryData as UpstreamBinaryData
        except ImportError:
            pass
        else:
            value = self.get_pubkey_id_from_(self.HARM_PUBKEY_BINARY,
                                             class_=UpstreamBinaryData)
            self.assertEqual(value, 'B7C32F6760E5CEC0')
