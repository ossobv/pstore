# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
django-pstore -- Python Protected Password Store (Django app)
Copyright (C) 2010,2012,2013,2015  Walter Doekes <wdoekes>, OSSO B.V.

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
from datetime import datetime
from random import getrandbits

from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import pre_delete
from django.utils.translation import ugettext_lazy as _

from pstorelib.crypt import encrypts

from pstore.db import Model, AsciiField, BlobField
from pstore.notify import (notify_object_deletion, notify_publickey_change,
                           notify_user_deletion)


class PublicKey(Model):
    """
    The user's public key. To reduce complexity, a user is only allowed to have
    one public key. If you want multiple public keys, you should create
    multiple users.

    The key property should hold the PGP public key block:

        -----BEGIN PGP PUBLIC KEY BLOCK-----
        Version: GnuPG v1.4.11 (GNU/Linux)
        [SP]
        mI0EULkrQAEEAKU++49M+QfiSTFJjWQ8Yyr+OKa0V90aNGbYNaGvfzlPVHNS+AwR
        ...

    or the obsolete ssh public key:

        ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA0IcrNyQLdVyCgpQtMfv/...

    Encrypted Property objects are encrypted using this public key.
    """
    user = models.OneToOneField(User, related_name='publickey')
    key = models.TextField(
        blank=False,
        help_text=_('The user\'s public key; can be in ssh authorized_key '
                    'format (OLD) or in PGP PUBLIC KEY format (NEW).'))
    description = models.CharField(
        max_length=255, blank=True,
        help_text=_('Human readable info about the key, e.g. the PGP key '
                    'uid (Alex Boonstra (TEST) <alex@example.com>).'))

    def __init__(self, *args, **kwargs):
        super(PublicKey, self).__init__(*args, **kwargs)

        # Used for the on-public-key-change signal. (Not setting pk, so no
        # recursion.)
        if self.pk:
            self.original = PublicKey(user=self.user, key=self.key,
                                      description=self.description)

    def diff(self, other):
        """
        Used by the changes notification mechanism. Will return only those
        properties that have changed between this version and ``other``. The
        code lives here because here we always know which properties we have.
        """
        changes = {}
        for property in ('id', 'user', 'key', 'description'):
            old = getattr(self, property)
            new = getattr(other, property)
            if old != new:
                changes[property] = {'old': old, 'new': new}
        return changes

    def key_type(self):
        if self.key.startswith('ssh-rsa '):
            return 'sshrsa'
        elif self.key.startswith('----'):
            return 'gpg'
        return 'unknown'

    def save(self, **kwargs):
        # Don't save useless CRs if we don't have to, and make sure we strip
        # excess LFs and space so the key_type() function works.
        self.key = self.key.strip().replace('\r', '')
        self.description = self.description.strip().replace('\r', '')

        ret = super(PublicKey, self).save(**kwargs)
        if hasattr(self, 'original'):
            notify_publickey_change(self.original, self)

        return ret

    def __unicode__(self):
        return _(u"%(user)s's %(key_type)s public key") % {
            'user': self.user, 'key_type': self.key_type()
        }


class Object(Model):
    """
    The general object identifier with permissions.

    Generally, when you want to store the password to a machine, you'll create
    a new Object which identifies the machine:

        machine = Object.objects.create(identifier='server.example.com')

    Next, you'll attach permissions to it:

        ObjectPerm.objects.create(object=machine, user=alex, can_write=True)
        ObjectPerm.objects.create(object=machine, user=harm, can_write=True)
        ObjectPerm.objects.create(object=machine, user=walter, can_write=False)

    Attach properties to it:

        # Public properties
        PubProp(machine, 'ssh-username', 'osso')
        PubProp(machine, 'ip-address', '1.2.3.4')
        # ^-- this would be a Property object with type=PUBLIC

        # Shared (encrypted) properties; there should always be one for each
        # "allowed" user.
        SharProp(machine, 'password', 'sEcReT!', walter)
        SharProp(machine, 'password', 'sEcReT!', alex)
        SharProp(machine, 'password', 'sEcReT!', harm)
        # ^-- this would be a Property object with type=SHARED

        #FUTURE## Private properties
        #FUTURE#PrivProp(machine, 'password-walter', 'wAlTeR!', walter)
        #FUTURE# ^-- this would be a Property object with type=PRIVATE

    Certain properties may be marked as "magic" by the associated tools. E.g.
    the "password" for automatic ssh login. The Object itself does not assign
    any meaning to it though.
    """
    identifier = AsciiField(max_length=255, unique=True)

    class Meta:
        permissions = (
            # Permissions to view not-owned objects (admins get this)
            ('view_any_object', _('View any object')),
        )

    def __unicode__(self):
        return self.identifier


class ObjectPerm(models.Model):
    """
    Who has read and write permissions for an Object.
    """
    object = models.ForeignKey(Object, related_name='allowed')
    user = models.ForeignKey(User)
    can_write = models.BooleanField()

    def __unicode__(self):
        dict = {'user': self.user, 'object': self.object}
        if self.can_write:
            return _('%(user)s can write %(object)s') % dict
        return _('%(user)s can read %(object)s') % dict


class Property(models.Model):
    """
    An Object can hold one or more properties. For public properties, there
    is only one record. For private/shared (encrypted) properties, there is one
    property per allowed user.

    The value is attached to the property instead to a separate model because
    less tables are nice and renaming properties is not a recommended action.

    This property points to a user instead of to a public key, since the user
    owns the property. The key is just a means of decrypting it.
    """
    BIT_PUBLIC = 0x1
    BIT_ENCRYPTED = 0x2

    TYPE_PUBLIC = BIT_PUBLIC                  # 1
    TYPE_PRIVATE = BIT_ENCRYPTED              # 2
    TYPE_SHARED = BIT_PUBLIC | BIT_ENCRYPTED  # 3

    TYPE_CHOICES = (
        (TYPE_PUBLIC, 'Public (unencrypted)'),
        # #FUTURE# (TYPE_PRIVATE, 'Private (encrypted)'),
        (TYPE_SHARED, 'Shared (encrypted)'),
    )

    created = models.DateTimeField(auto_now_add=True)
    object = models.ForeignKey(Object, related_name='properties')
    name = AsciiField(
        max_length=255,
        help_text=_('The property identifier/name.'))
    type = models.PositiveSmallIntegerField(
        choices=TYPE_CHOICES,
        default=TYPE_PUBLIC, help_text=_('Property properties ;-)'))

    # Make sure you defer('value') unless you need it!
    value = BlobField(blank=True)

    user = models.ForeignKey(User, blank=True, null=True, default=None)

    class Meta:
        unique_together = ('object', 'name', 'user')
        verbose_name = _('property')
        verbose_name_plural = _('properties')

    def enctype(self):
        """
        What kind of encryption this property is encrypted with. All properties
        for the same user are always encrypted with the same key. Keep that in
        mind when you're checking the encryption type of multiple properties.
        (Less queries is better.)
        """
        if bool(self.type & self.BIT_ENCRYPTED):
            assert self.user_id is not None
            return PublicKey.objects.get(user__id=self.user_id).key_type()
        assert self.user_id is None
        return 'none'

    def __unicode__(self):
        return _('%(object)s -> %(name)s (%(user)s)') % {
            'object': self.object, 'name': self.name, 'user': self.user
        }


class Nonce(models.Model):
    """
    To authenticate users, we use encrypted nonces. We generate a random value,
    encrypt the data using the user's public key and hand out that nonce.

    When the user wants to do any writing, we require him to send a recent
    valid nonce. If the user has a valid nonce, we'll know that he has the
    power to decode messages using his own private key: i.e. the user is
    authenticated.

    Restrictions:
    - A nonce shall be used as most once to avoid replay attacks.
    - The user can request a number of nonces, but to avoid DoSing, we should
      limit that to a finite amount. And, we should limit the usability time,
      but not too low, since an upload might take a while if we're dealing with
      large documents.
    """
    MAX_AGE = 300       # 5 minutes should be enough to upload all properties
    MIN_LENGTH = 32     # we generate nonces of 32 bytes
    MAX_LENGTH = 32     # exactly 32

    created = models.DateTimeField(auto_now_add=True)  # expiry depends on this
    user = models.ForeignKey(User)
    value = BlobField()
    encrypted = BlobField()

    @classmethod
    def is_sane(cls, value):
        return cls.MIN_LENGTH <= len(value) <= cls.MAX_LENGTH

    @classmethod
    def is_sane_b64(cls, value):
        if not isinstance(value, basestring):
            return False
        b64_min_length = int(cls.MIN_LENGTH * 4.0 / 3)
        b64_max_length = int((cls.MAX_LENGTH + 3.0) * 4 / 3)
        return b64_min_length <= len(value) <= b64_max_length

    def is_expired(self):
        diff = datetime.now() - self.created
        try:
            diff = diff.total_seconds()
        except AttributeError:  # python2.6-
            diff = diff.days * 86400.0 + diff.seconds  # ignoring mu-seconds
        return diff > self.MAX_AGE

    def generate(self):
        assert not self.value

        value = []
        bytes = 32
        random = getrandbits(bytes * 8)  # is this random enough?

        # Long-to-bytes in a little endian fashion.
        while random:
            value.append('%c' % (random & 0xff),)
            random >>= 8
        while len(value) < bytes:
            value.append('\0')  # most significant bytes 0?

        self.value = ''.join(value)
        assert self.is_sane(self.value)

    def encrypt(self):
        assert self.value
        assert self.user
        assert not self.encrypted

        publickey = self.user.publickey
        self.encrypted = encrypts(self.value, public_key=publickey.key)

    def save(self, **kwargs):
        # Make sure we have a nonce.
        if not self.value:
            self.generate()
        # Make sure we have an encrypted version of it.
        if not self.encrypted:
            self.encrypt()

        return super(Nonce, self).save(**kwargs)


# Time for some signal handling. The publickey change notification is not
# handled through signals but in the save() method.

def on_object_delete(instance, **kwargs):
    notify_object_deletion(object=instance)
pre_delete.connect(on_object_delete, sender=Object)


def on_user_delete(instance, **kwargs):
    # We pass the public key and the objects because if notify had to know
    # about them, we'd get a circular dependency.
    try:
        publickey = PublicKey.objects.get(user=instance)
    except PublicKey.DoesNotExist:
        publickey = None

    object_pks = (ObjectPerm.objects.filter(user=instance)
                  .values_list('object', flat=True))
    objects = Object.objects.filter(pk__in=object_pks).order_by('identifier')

    notify_user_deletion(user=instance, publickey=publickey, objects=objects)
pre_delete.connect(on_user_delete, sender=User)
