# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
django-pstore -- Python Protected Password Store (Django app)
Copyright (C) 2013,2015  Walter Doekes <wdoekes>, OSSO B.V.

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
from base64 import b64encode
from email.Utils import formataddr

from django.contrib.admin.models import DELETION, LogEntry
from django.contrib.contenttypes.models import ContentType
from django.conf import settings
from django.core.mail import send_mail
from django.db.models import Q
from django.utils.encoding import force_unicode


def collect_object_info(property_qs, user):
    MAX_PROPERTY_SIZE = 4096

    info = []
    # BEWARE: For the SQLite3 backend, the LENGTH() is incorrect!
    properties = (property_qs.filter(Q(user=None) | Q(user=user))
                  .filter(Q(user=None) | Q(user=user))
                  .defer('value')
                  .extra(select={'size': 'LENGTH(value)'})
                  .order_by('name'))

    for property in properties:
        # Only get value if size is smaller than MAX_PROPERTY_SIZE.
        readable = None
        value = None
        if property.size <= MAX_PROPERTY_SIZE:
            value = property.value

        # The readable version can be shown when:
        # (a) it isn't encrypted
        # (b) it the value is found
        # (c) the value doesn't contain binary non-utf8 data
        if property.type & property.BIT_ENCRYPTED:
            readable = '(encrypted value of size %d)' % (property.size,)
        elif value is None:
            readable = '(value of size %d)' % (property.size,)
        else:
            try:
                readable = value.decode('utf-8')
            except UnicodeDecodeError:
                readable = None
            else:
                if any(ord(i) < 0x20 and i not in '\t\r\n'
                       for i in readable):
                    readable = None
                elif any(len(i) > 119  # mail readers can cope with 120+
                         for i in readable.split('\n')):
                    readable = None
            if readable is None:
                readable = '(non-printable)'
        # Add the property to the mail
        info.append('[%s]' % (property.name,))
        info.append('  %s' % ('\n  '.join(i.rstrip()
                              for i in readable.split('\n')).rstrip(),))
        if value is not None:
            info.append('; base64 encoded data')
            encoded = b64encode(value)
            for i in range(0, len(encoded), 70):
                info.append('  %s' % (encoded[i:(i + 70)],))
        info.append('')

    return info


def notify_object_deletion(object):
    """
    Send mail to all property owners when an object is removed.

    If a rogue admin goes around deleting objects we'll attempt to rescue some
    of the data. Decoding the shared properties from this notification mail
    should be easy enough if you have the right tools and the right private
    key.
    """
    # Compile mail info.
    subject = '[pstore] deleted object %s' % (object.identifier,)
    fromaddr = settings.DEFAULT_FROM_EMAIL

    for permission in object.allowed.select_related('user').all():
        user = permission.user

        # Skip if user doesn't have e-mail.
        if not user.email:
            continue

        # Extend mail info.
        toaddr = formataddr((user.get_full_name(), user.email))
        body = ['Object %s was deleted from the pstore!\n\n'
                'Properties are listed below.\n' % (object.identifier,)]
        body.extend(collect_object_info(property_qs=object.properties,
                                        user=user))
        flatbody = '\n'.join(body)

        # Write an admin log entry for every individual user and store
        # the flatbody there. We don't want it mailed to an insecure
        # location if we can help it.
        entry = LogEntry.objects.create(
            user=user,  # NOTE: not the *deleting* user
            content_type=ContentType.objects.get_for_model(object),
            object_id=object.pk,
            object_repr=force_unicode(object),
            action_flag=DELETION,
            change_message=flatbody
        )

        flatbody = ('Object %s was deleted from the pstore!\n\n'
                    'Details about removed properties can be found in '
                    'the admin log %d.\n' % (object.identifier, entry.id))

        # Send out a mail.
        if settings.DEBUG:
            print 'Sending mail to:', toaddr
            print '--'
            print flatbody
            print '--'
        else:
            send_mail(subject, flatbody, fromaddr, (toaddr,))


def notify_publickey_change(old_publickey, new_publickey):
    """
    Send mail to ADMINS and the user when a public key is changed.

    You'll want a notification in this case, because all new shared properties
    will hold values encrypted with the new public key while the old ones are
    unaltered. I.e. manual intervention is required unless you like to see the
    pstore store go "out of sync".
    """
    user = old_publickey.user

    # Compile mail info.
    subject = '[pstore] public key changed for %s' % (user.username,)
    fromaddr = settings.DEFAULT_FROM_EMAIL
    user_toaddrs = (formataddr((user.get_full_name(), user.email)),)
    admin_toaddrs = tuple(formataddr(i) for i in settings.ADMINS)

    body = ['Public key "%s" was changed in the pstore!\n\n'
            'Beware that adding/changing new shared properties might result '
            'in encryption with a different public key.\n' % (old_publickey,)]

    changes = old_publickey.diff(new_publickey)
    del changes['id']  # old never has a pk/id

    for change in sorted(changes.keys()):
        old, new = changes[change]['old'], changes[change]['new']
        body.append('[%s]' % (change,))
        body.append('  %s' % (old.replace('\n', '\n  '),))
        body.append('; new')
        body.append('  %s' % (new.replace('\n', '\n  '),))
        body.append('')

    flatbody = '\n'.join(body)

    # Send out a mail.
    if settings.DEBUG:
        print 'Sending mail to:', user_toaddrs + admin_toaddrs
        print '--'
        print flatbody
        print '--'
    else:
        # Two separate mails. The user does not need to know who the admins
        # are.
        for toaddrs in (user_toaddrs, admin_toaddrs):
            send_mail(subject, flatbody, fromaddr, toaddrs)


def notify_user_deletion(user, publickey, objects):
    """
    Send mail to admins when a user is removed.

    When a user goes, we'll want a record of the properties that went with it.
    This one should NOT be sent to the user but to the ADMINS instead.
    """
    objects = list(objects)  # we'll be iterating over it twice

    # Compile mail info.
    subject = '[pstore] deleted user %s' % (user.username,)
    fromaddr = settings.DEFAULT_FROM_EMAIL
    admin_toaddrs = tuple(formataddr(i) for i in settings.ADMINS)

    body = ['User %s was deleted from the pstore!\n\n'
            'The user had access to the properties tied to these objects:' %
            (user.username,)]
    for object in objects:
        body.append('- %s' % (object.identifier,))
    body.append('')

    if publickey:
        body.append('\nPublic key:\n')
        body.append('[description]\n  %s\n' %
                    (publickey.description.replace('\n', '\n  '),))
        body.append('[key]\n  %s' % (publickey.key.replace('\n', '\n  '),))
        body.append('')

    for object in objects:
        body.append('\nObject %s:\n' % (object.identifier,))
        body.extend(collect_object_info(property_qs=object.properties,
                                        user=user))
    flatbody = '\n'.join(body)

    # Do we have an admin log? Then store the flatbody there. We don't
    # want it mailed to an insecure location if we can help it.
    ct = ContentType.objects.get_for_model(user)
    try:
        entry = LogEntry.objects.get(content_type=ct, object_id=user.id,
                                     action_flag=DELETION)
    except LogEntry.DoesNotExist:
        entry = None
    else:
        entry.change_message += flatbody
        entry.save()
        flatbody = ('User %s was deleted from the pstore!\n\n'
                    'Details about removed objects can be found in the admin '
                    'log %d.\n' % (user.username, entry.id))

    # Send out a mail.
    if settings.DEBUG:
        print 'Sending mail to:', admin_toaddrs
        print '--'
        print flatbody
        print '--'
    else:
        send_mail(subject, flatbody, fromaddr, admin_toaddrs)
