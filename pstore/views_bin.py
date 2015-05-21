# vim: set ts=8 sw=4 sts=4 et ai tw=79:
"""
django-pstore -- Python Protected Password Store (Django app)
Copyright (C) 2012,2013,2015  Walter Doekes <wdoekes>, OSSO B.V.

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
from datetime import datetime, timedelta
from os import chmod, unlink

from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.db import connection
from django.db.models import Q
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_GET, require_POST

from pstorelib.bytes import BytesIO
from pstorelib.server import urlunquote

from pstore.decorators import audit_view, nonce_required
from pstore.http import EncryptedResponse, HttpError, VoidResponse
from pstore.models import Nonce, Object, ObjectPerm, Property
from pstore.security import get_object_or_403


# NOTE: If the user is a superuser, the results to certain lookups will be 200
# or 404. If the user is a mere mortal, lookups that do not return 200 will
# return 403.


def create_property(object, property, file, user):
    # If isinstance(file, InMemoryUploadedFile) then file.field_name contains
    # property as well. The TemporaryUploadedFile doesn't have it though.

    if user:
        ptype = Property.TYPE_SHARED
        if file.size == 0:
            raise HttpError(400, 'encrypted properties cannot be 0 bytes in '
                                 'length')
    else:
        ptype = Property.TYPE_PUBLIC

    # Depending on the file size, we either get an InMemoryUploadedFile or a
    # TemporaryUploadedFile.
    if hasattr(file, 'temporary_file_path'):
        # Tricks! We'll use a custom INSERT on localhost. Otherwise we'll
        # run into the MySQL max_packet_size limit.
        tempname = file.temporary_file_path()
        data = '...loading...'
    else:
        tempname = None
        data = file.read()
        if len(data) != file.size:
            raise HttpError(
                500, 'file read returned wrong amount of bytes',
                ('We expected to read %d bytes at once from %s. We only got '
                 '%d bytes.' % (file.size, file.name, len(data))))

    prop = Property.objects.create(object=object, name=property,
                                   type=ptype, value=data, user=user)

    # If tempname then we've only written a dummy value thusfar. Update it
    # to the real value.
    if tempname:
        # We use LOAD_FILE() because it speeds up the writing by a factor
        # three. We expect you to run the MySQLd on localhost for now..
        if (connection.settings_dict['HOST'] not in
                ('', 'localhost', '127.0.0.1')):
            raise HttpError(
                413, 'request too large (mysqld infrastructure)',
                ('mysqld can only use LOAD_FILE() on localhost and the DB '
                 'server seems to be running on %s' %
                 (connection.settings_dict['HOST'],)))
        # MySQLd must get read powers.
        try:
            chmod(tempname, 0604)
        except Exception, e:
            raise HttpError(
                413, 'request too large (webserver permissions)',
                ('For mysqld to do load LOAD_FILE() on %s, we need to alter '
                 'file permissions, we got: %s' % (tempname, e)))
        # Try to read the file.
        try:
            cursor = connection.cursor()
            cursor.execute('''
                UPDATE pstore_property SET value = LOAD_FILE(%s)
                WHERE id = %s;
            ''', (tempname, prop.id))
        except Exception, e:
            # Tip #1:
            #   /etc/apparmor.d/local/usr.sbin.mysqld:
            #     /tmp/* r,
            #
            # Tip #2:
            #   mysql> UPDATE mysql.user SET file_priv = 'Y'
            #          WHERE user = 'pstore' AND host = 'localhost'
            #          AND file_priv = 'N'; FLUSH PRIVILEGES;
            #
            # Tip #3:
            #   /etc/mysql/my.cnf:
            #     # If you're doing replication, you must use MIXED or
            #     # ROW based replication. Otherwise LOAD_FILE will fail.
            #     binlog_format = MIXED
            #
            raise HttpError(
                413, 'request too large (mysqld permissions)',
                ('mysqld LOAD_FILE failed for %s, check apparmor. Check '
                 'File_Priv mysql permissions, check @@max_allowed_packet, '
                 'check @@secure_file_priv: %s' % (tempname, e)))
        finally:
            # Remove access to the file asap.
            unlink(tempname)
            # Close the cursor here. The http middleware will commit the
            # transaction when/if done.
            cursor.close()


# NOT nonce_required.. obviously..
@require_POST
@audit_view('creates nonce')
def create_nonce(request):
    """
    One of the few views that does not require a valid nonce.
    """
    # Query strings:
    u = request.GET.get('u', None)  # create nonce for a user
    if not u:
        raise Http404('Bad call')

    # FIXME: instead of returning 403, we should hand out a bogus nonce instead
    # >:-) But then we should do that below too..
    # and what to use for publickey.key_type?
    user = get_object_or_403(User, username=u)

    # Prune old nonces.. might as well do that here.
    old = datetime.now() - timedelta(seconds=Nonce.MAX_AGE)
    Nonce.objects.filter(created__lt=old).delete()

    # Check whether this user has created enough nonces already.
    max_queued_nonces = 10
    if Nonce.objects.filter(user=user).count() > max_queued_nonces:
        raise PermissionDenied()

    # Ok, create a new one.
    nonce = Nonce.objects.create(user=user)

    # Response:
    return EncryptedResponse(data=nonce.encrypted,
                             enctype=user.publickey.key_type())


@nonce_required
@require_GET
@audit_view('reads single property')
def get_property(request, object_identifier, property_name):
    # Query strings:
    u = request.GET.get('u', None)  # filter by user

    # Decode object_identifier and property_name:
    object_identifier = urlunquote(object_identifier)
    property_name = urlunquote(property_name)

    # Query:
    qs = Property.objects.filter(
        object__identifier=object_identifier,
        name=property_name)
    if u:
        qs = qs.filter(Q(user=None) | Q(user__username=u))
    else:
        qs = qs.filter(user=None)

    # Check authorization:
    if request.user.has_perm('pstore.view_any_object'):
        pass
    elif not ObjectPerm.objects.filter(
            object__identifier=object_identifier,
            user=request.user).exists():
        raise PermissionDenied('Not staff and not permitted')

    # Results:
    items = list(qs[0:2])
    if not items:
        # Was this because we didn't have permission or because there
        # simply wasn't a property?
        if (request.user.has_perm('pstore.view_any_object') and
                not Property.objects.filter(
                    object__identifier=object_identifier,
                    name=property_name).exists()):
            raise Http404('No such property')
        raise PermissionDenied('Not staff or not permitted')

    if len(items) > 1:
        class_ = Property.MultipleObjectsReturned
        raise class_('get() returned more than one Property. Lookup parameters'
                     ' were %r' % ({'object': object_identifier,
                                    'name': property_name},))

    # TODO: if the value is really large, we should somehow write it to disk
    # before passing it around.
    property = items[0]
    file = BytesIO(property.value)

    # Response:
    return EncryptedResponse(fp=file, enctype=property.enctype())


@nonce_required
@require_POST
@audit_view('sets or replaces a property', mutates=True)
def set_property(request, object_identifier, property_name):
    author = request.user  # FIXME

    # Check the rest of the arguments.
    if len(request.GET) != 0:
        raise NotImplementedError('Unexpected GET args', request.GET)
    if len(request.POST) != 1:  # nonce was here..
        raise NotImplementedError('Unexpected POST args', request.POST)

    # Docode URI arguments.
    object_identifier = urlunquote(object_identifier)
    property_name = urlunquote(property_name)

    # Which users?
    usernames = [i.name for i in request.FILES.getlist(property_name)]
    assert usernames

    # Are they the-public-user?
    if usernames == ['*']:
        is_public = True
        users = None
        users_dict = {'*': None}  # the public-user
    elif all(i != '*' for i in usernames):
        is_public = False
        users = list(User.objects.filter(username__in=usernames))
        if len(users) != len(usernames):
            raise Exception('FIXME-EXCEPTION')
        users_dict = dict((i.username, i) for i in users)
    else:
        raise Exception('FIXME-EXCEPTION')

    # Autocreate object if it didn't exist yet. Next, make *sure* that 'author'
    # that we found in the nonce is a valid writer.
    if users:
        obj, created = Object.objects.get_or_create(
            identifier=object_identifier)
    else:
        try:
            obj = Object.objects.get(identifier=object_identifier)
        except Object.DoesNotExist:
            raise Http404('Refusing to create an object automatically')
        else:
            created = False

    if created:
        # We need a list of users if this is a new entry! Yes.. that means
        # that we *must* have an encrypted property for the machine to be
        # created. Let that be the case for now.
        assert users

        # Author must be in the list of users too.
        if author not in users:
            raise PermissionDenied('Author is not in list of users',
                                   author.username)

        # Give everyone admin perms for now. We shall devise some kind of
        # scheme to tell admins from readers apart in the future.
        for user in users:
            ObjectPerm.objects.create(object=obj, user=user, can_write=True)

    else:
        # Check that author has write powers.
        # TODO: we could allow SU-users to do stuff..
        if not obj.allowed.filter(can_write=True, user=author).exists():
            raise PermissionDenied('Author has no write powers for object',
                                   author.username)

        if not is_public:
            # The amount of received files must obviously be equal to the
            # number of allowed users. Checks against the individual files is
            # done below. We compare the user list to make sure we don't get
            # too few or too many.
            if set(i.user for i in obj.allowed.all()) != set(users):
                raise PermissionDenied('Object exists already and supplied '
                                       'list of users differs')

    # TODO: extra audit stuff here. do more?
    oldies = list(Property.objects.filter(object=obj, name=property_name)[0:1])
    if oldies:
        if oldies[0].type == Property.TYPE_PUBLIC and not is_public:
            # LOG: switching property from public to shared
            pass
        elif oldies[0].type == Property.TYPE_SHARED and is_public:
            # LOG: switching property from shared to public
            pass

    # Purge the old properties..
    Property.objects.filter(object=obj, name=property_name).delete()
    # ... and create new ones.
    for file in request.FILES.getlist(property_name):
        user = users_dict[file.name]
        create_property(object=obj, property=property_name, file=file,
                        user=user)

    return VoidResponse()


@nonce_required
@require_POST
@audit_view('updates properties and/or permissions', mutates=True)
def update_properties(request, object_identifier):
    if len(request.GET) != 0:
        raise NotImplementedError('Unexpected GET args', request.GET)
    if len(request.POST) != 1:  # only the nonce_b64 should be here
        raise NotImplementedError('Unexpected POST args', request.POST)

    # Decode object_identifier:
    object_identifier = urlunquote(object_identifier)

    # Check authorization and existence:
    if request.user.has_perm('pstore.view_any_object'):
        obj = get_object_or_404(Object, identifier=object_identifier)
    else:
        obj = get_object_or_403(Object, identifier=object_identifier)
    try:
        ObjectPerm.objects.get(object=obj, user=request.user, can_write=True)
    except ObjectPerm.DoesNotExist:
        raise PermissionDenied('No permissions for user', request.user)

    # Fetch users and do a few basic checks on them. Below, during the Property
    # create loop, we'll do some more checks.
    usernames = []
    for property_name in request.FILES.keys():
        for file in request.FILES.getlist(property_name):
            username = file.name
            usernames.append(username)
    usernames = set(usernames)
    users = dict([(i.username, i) for i in
                  User.objects.filter(username__in=usernames)])
    if len(users) != len(usernames):
        raise Exception('FIXME-EXCEPTION: user count invalid')

    # XXX: assert that user is in usernames!

    # TODO: do more assertions on the users here..
    # TODO: add to audit log the attempted move of userset X to userset Y

    # Fetch files and re-set properties. Here we won't accept transparent
    # switches of public to shared properties.
    for property_name in request.FILES.keys():
        # TODO: ensure that we have a file for every user for every key
        # TODO: check public/shared properties for swapperony
        Property.objects.filter(object=obj, name=property_name).delete()

        for file in request.FILES.getlist(property_name):
            # We only add new shared (encrypted) properties, we don't need to
            # touch the public ones.
            user = users[file.name]
            create_property(object=obj, property=property_name, file=file,
                            user=user)

    # Update permissions. For now, we'll only use the can_write, since we don't
    # have a means of communicating that state yet.
    # TODO: (a) audit log here?
    # TODO: (b) don't delete permitted users and add a created column to
    # ObjectPerm?
    # TODO: (c) double check that there are no user-properties for disallowed
    # users left?
    currently_allowed = set([i.user for i in
                             (ObjectPerm.objects.filter(object=obj)
                              .select_related('user'))])
    del currently_allowed  # fixme.. use this
    # XXX: take currently_allowed, remove now-allowed:
    # delete the leftovers
    # add the not-in-currently_allowed
    ObjectPerm.objects.filter(object=obj).delete()
    for user in users.values():
        ObjectPerm.objects.create(object=obj, user=user, can_write=True)

    return VoidResponse()
