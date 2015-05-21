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
from base64 import b64encode
from collections import defaultdict

from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_GET

from pstorelib.server import urlunquote

from pstore.decorators import audit_view, nonce_required
from pstore.models import Object, ObjectPerm, PublicKey, Property
from pstore.security import get_object_or_403
from pstore.xhr import JsonResponse


@nonce_required
@require_GET
@audit_view('reads object details')
def get_object(request, object_identifier):
    """
    Get a single object. You get verbose info.

    Note that if you want info about the properties for a different user,
    you'll need to redo the query with that user id.
    """
    # Decode object_identifier.
    object_identifier = urlunquote(object_identifier)

    # Check authorization and existence:
    u = request.GET.get('u', None)
    if request.user.has_perm('object.view_any_object'):
        obj = get_object_or_404(Object, identifier=object_identifier)
    elif u != request.user.username:
        raise PermissionDenied()
    else:
        obj = get_object_or_403(Object, identifier=object_identifier)

    # Check if the user is allowed to view this.
    try:
        obj.allowed.get(user=request.user)
    except ObjectDoesNotExist:
        if not request.user.has_perm('object.view_any_object'):
            raise PermissionDenied()

    # Get lots of info for this object.
    result = {}

    # Get the allowed users.
    allowed = obj.allowed.select_related('user')
    result['users'] = dict([(i.user.username, {'can_write': i.can_write})
                            for i in allowed])

    # Get a list of properties.
    propqs = Property.objects.filter(object=obj)
    if u:
        propqs = propqs.filter(Q(user__username=u) | Q(user=None))
    else:
        propqs = propqs.filter(user=None)
    # BEWARE: For the SQLite3 backend, the LENGTH() is incorrect!
    propqs = propqs.extra(select={'size': 'LENGTH(value)'})
    properties = set(propqs.values_list('id', 'name', 'type', 'size', 'user'))

    # Get the values, but only for small properties.
    small_property_ids = [i[0] for i in properties if i[3] <= 2048]

    # https://code.djangoproject.com/ticket/9619
    # We cannot do values_list when using SQLite3.
    # #property_values = dict(Property.objects
    # #                       .filter(id__in=small_property_ids)
    # #                       .values_list('id', 'value'))
    property_qs = Property.objects.filter(id__in=small_property_ids)
    property_values = dict((i.id, i.value)
                           for i in property_qs.only('id', 'value'))

    # Put properties in the results dictionary.
    result['properties'] = {}
    enctype, encuid = None, None  # cache encryption type

    for property_id, name, type, size, user in properties:
        assert type in (Property.TYPE_PUBLIC, Property.TYPE_SHARED)

        # Cache the enctype so we don't have to look it up for every property.
        if user:
            if not enctype:
                encuid = user
                enctype = PublicKey.objects.get(user__id=user).key_type()
                assert enctype
            else:
                assert encuid == user, '%r == %r' % (encuid, user)

        # These are always returned.
        info = {'data': None,
                'size': size,
                'enctype': ('none', enctype)[bool(user)]}

        # If data is small enough, it is set too.
        if property_id in property_values:
            info['data'] = b64encode(property_values[property_id])

        result['properties'][name] = info

    # If a superuser called and wants to know what properties there are, add
    # those.
    if not u:
        # Fetch property names for the properties.
        for name, type in (Property.objects.filter(object=obj)
                           .exclude(user=None)
                           .values_list('name', 'type').distinct()):
            assert type == Property.TYPE_SHARED

            # These are always returned, but this time we have no useful info
            # for the caller.
            info = {'data': None, 'size': None, 'enctype': None}

            result['properties'][name] = info

    return JsonResponse(request, result)


@nonce_required
@require_GET
@audit_view('lists objects+info')
def list_objects(request):
    # Check authorization and existence:
    u = request.GET.get('u', None)
    if request.user.has_perm('object.view_any_object'):
        pass
    elif u != request.user.username:
        raise PermissionDenied()

    # Query strings:
    q = request.GET.get('q', None)  # filter against identifier
    v = request.GET.get('v', None) and True  # list more info

    # Query:
    qs = Object.objects.all()  # no ordering here, that's up to the client
    if q:
        qs = qs.filter(identifier__icontains=q)
    if u:
        qs = qs.filter(allowed__user__username=u)

    # Result:
    if v:
        # Listify.
        qs = list(qs.values_list('id', 'identifier'))
        # Fetch the related allow lists in a single query.
        allowed = ObjectPerm.objects.filter(object__id__in=[i[0] for i in qs])
        allowed = list(allowed.values_list('object', 'user', 'can_write'))
        users = User.objects.filter(id__in=set([i[1] for i in allowed]))
        # Dictify.
        users = dict(users.values_list('id', 'username'))
        allowed_dict = defaultdict(dict)
        for object_id, user_id, can_write in allowed:
            allowed_dict[object_id][users[user_id]] = {'can_write': can_write}
        # Combine.
        result = {}
        for object_id, identifier in qs:
            # Only add the user allow-list to the all-objects listing. If you
            # want property details, use single-object lookups.
            result[identifier] = {'users': allowed_dict[object_id]}
    else:
        result = dict((i, True)
                      for i in qs.values_list('identifier', flat=True))

    return JsonResponse(request, result)


@nonce_required
@require_GET
@audit_view('search properties')
def search_properties(request):
    # Check authorization and existence:
    u = request.GET.get('u', None)
    if request.user.has_perm('object.view_any_object'):
        pass
    elif u != request.user.username:
        raise PermissionDenied()

    # Query:
    qs = Property.objects.all()  # no ordering here, that's up to the client
    if u:
        qs = qs.filter(object__allowed__user__username=u)

    # More queries (observe that "icontains" search depends on the DB
    # backend to work insensitively; MySQL blob does *not* work).
    if 'propkey_icontains' in request.GET:
        qs = qs.filter(name__icontains=request.GET['propkey_icontains'])
    if 'propvalue_icontains' in request.GET:
        # Yuck. That length should've been memoized.
        qs = (qs
              .filter(type=Property.TYPE_PUBLIC,
                      value__icontains=request.GET['propvalue_icontains'])
              .extra(where=['LENGTH(value) <= 2048']))

    # First sanity check:
    if qs.count() > 100:
        raise PermissionDenied('too many results')

    # Fetch extra properties we need:
    qs = qs.extra(select={'size': 'LENGTH(value)'})
    qs = qs.select_related('object')
    qs = qs.values_list('id', 'object__identifier', 'name', 'type', 'size')

    machines = {}
    for id_, identifier, propkey, proptype, size in qs:
        propvalue = None
        if proptype == Property.TYPE_PUBLIC and size <= 2048:
            propvalue = (Property.objects.filter(id=id_)
                         .values_list('value', flat=True)[0])

        info = {
            'data': propvalue,
            'size': size,
            'enctype': ('none', 'any')[proptype != Property.TYPE_PUBLIC],
        }
        if propvalue:
            info['data'] = b64encode(propvalue)

        if identifier not in machines:
            machines[identifier] = {'properties': {}}
        machines[identifier]['properties'][propkey] = info

    return JsonResponse(request, machines)


@require_GET
@nonce_required
@audit_view('lists users+info')
def list_users(request):
    # Query strings:
    q = request.GET.getlist('q')

    # Query:
    qs = PublicKey.objects.filter(user__is_active=True).select_related('user')
    if q:
        filter = Q()
        for username in q:
            filter |= Q(user__username=username)
        qs = qs.filter(filter)

    result = {}
    for object in qs:
        result[object.user.username] = {
            'key': object.key,
            'description': object.description,
        }

    return JsonResponse(request, result)


@nonce_required
@require_GET
@audit_view('validates db consistency')
def validate(request):
    if not request.user.has_perm('object.view_any_object'):
        raise PermissionDenied()

    tpub, tshar = Property.TYPE_PUBLIC, Property.TYPE_SHARED

    errors = []

    # Assert that all objects have an allowed list.
    for object in Object.objects.filter(allowed=None):
        errors.append((
            'Object', object.id,
            '%s has no allowed list' % (object.identifier,),
            'Add ObjectPerm items',
        ))

    # FIXME: code below is broken for objects with both readers and writers..
    # # Assert that all objects have someone who can write.
    # #for object in Object.objects.filter(allowed__can_write=False):
    # #   errors.append((
    # #       'Object', object.id,
    # #       '%s does not have an admin' % (object.identifier,),
    # #       'Add ObjectPerm items with can_write powers',
    # #   ))

    # Check property types.
    for property in (Property.objects.exclude(type__in=[tpub, tshar])
                     .defer('value')):
        errors.append((
            'Property', property.id,
            ('%s -> %s has type %d' %
             (property.object.identifier, property.name, property.type)),
            'Alter the type to %d or %d' % (tpub, tshar),
        ))

    # Check property types (PUBLIC must not have a user).
    for property in (Property.objects.filter(type=tpub, user__isnull=False)
                     .defer('value')):
        errors.append((
            'Property', property.id,
            ('%s -> %s (type %d) has a user' %
             (property.object.identifier, property.name, tpub)),
            'Type %d properties should not have a user' % (tpub,),
        ))

    # Check property types (SHARED must have a user).
    for property in (Property.objects.filter(type=tshar, user__isnull=True)
                     .defer('value')):
        errors.append((
            'Property', property.id,
            ('%s -> %s (type %d) does not have a user' %
             (property.object.identifier, property.name, tshar)),
            'Type %d properties should have a user' % (tshar,),
        ))

    # Check that all type SHARED objects have as many records as there are
    # allowed users.
    for object in Object.objects.all():
        user_ids = [i.user_id for i in object.allowed.all()]
        shared_properties = (Property.objects.filter(object=object, type=tshar)
                             .defer('value').order_by('name'))

        per_property = defaultdict(list)
        for property in shared_properties:
            per_property[property.name].append(property.user_id)

        for property_name, property_user_ids in per_property.iteritems():
            if (len(property_user_ids) != len(user_ids) or
                    set(property_user_ids) != set(user_ids)):
                errors.append((
                    'Object', object.id,
                    ('%s -> %s has wrong number of properties' %
                     (object.identifier, property_name)),
                    ('The allowed users is out of sync with the amount of '
                     'properties for this object.'),
                ))

    return JsonResponse(request, {'errors': errors})
