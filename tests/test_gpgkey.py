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
from base64 import b64decode
from datetime import datetime
from unittest import TestCase

from pstorelib.gpgkey import get_pubkey_expiry, get_pubkey_id


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

    TEST1_KEY_WITH_1Y_EXPIRY = '''\
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
Z0PrRJRebr4=
=24I+
-----END PGP PUBLIC KEY BLOCK-----
'''
    TEST1_KEY_WITH_2Y_EXPIRY = '''\
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
FMBf4Lt1qLD2MpquDHUgwgV5k1edAKM=
=VWCK
-----END PGP PUBLIC KEY BLOCK-----
'''

    def test_get_pubkey_id_from_ascii(self):
        value = get_pubkey_id(self.HARM_PUBKEY_ASCII)
        self.assertEqual(value, 'B7C32F6760E5CEC0')

    def test_get_pubkey_id_from_binary(self):
        value = get_pubkey_id(self.HARM_PUBKEY_BINARY)
        self.assertEqual(value, 'B7C32F6760E5CEC0')

    def test_test1_1y_expiry(self):
        """
        Test a key with multiple signature packets from the same master key.

            :public key packet:
            :user ID packet: "Test1 <test1@example.com>"
            :signature packet: algo 1, keyid F23A739F45D823EE
                    hashed subpkt 2 len 4 (sig created 2024-10-29)
                    hashed subpkt 9 len 4 (key expires after 1y0d0h2m)
            :signature packet: algo 1, keyid F23A739F45D823EE
                    hashed subpkt 2 len 4 (sig created 2024-10-29)
                    hashed subpkt 9 len 4 (key expires after 3y0d0h0m)
            :public sub key packet:
            :signature packet: algo 1, keyid F23A739F45D823EE
                    hashed subpkt 2 len 4 (sig created 2024-10-29)
                    hashed subpkt 9 len 4 (key expires after 1y0d0h2m)

        We expect 1y expiry = 2025.
        """
        value = get_pubkey_expiry(self.TEST1_KEY_WITH_1Y_EXPIRY)
        self.assertEqual(value, datetime(2025, 10, 29, 11, 7, 35))

    def test_test1_2y_expiry(self):
        """
        Test a key with multiple signature packets from the same master key.

        Has the same packets are the test1_1y_expiry, but additionally this:

            :signature packet: algo 1, keyid F23A739F45D823EE
                    hashed subpkt 2 len 4 (sig created 2024-10-29)
                    hashed subpkt 9 len 4 (key expires after 2y0d0h5m)

        It should there for use this 2y for the public sub key packet.
        We expect 2y expiry = 2026.
        """
        value = get_pubkey_expiry(self.TEST1_KEY_WITH_2Y_EXPIRY)
        self.assertEqual(value, datetime(2026, 10, 29, 11, 10, 41))
