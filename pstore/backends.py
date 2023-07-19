import logging

from django.contrib.auth.backends import get_user_model

try:
    from kleides_dssoclient.backends import DssoLoginBackend
except ImportError:
    DssoLoginBackend = None

log = logging.getLogger(__name__)


if DssoLoginBackend:
    class PstoreDssoLoginBackend(DssoLoginBackend):
        create_unknown_user = False

        def authenticate(self, request=None, dsso_mapping=None):
            '''
            Custom backend that checks email instead of username,
            requires superuser privs and does not create users.
            '''
            if not dsso_mapping:
                return
            if not dsso_mapping.get('email'):
                return
            # Only allow superusers.
            #if dsso_mapping.get('is_superuser') not in ('True', 'true', '1'):
            #    return

            user = None
            email = dsso_mapping['email']
            UserModel = get_user_model()

            try:
                user = UserModel.objects.get(email=email)
            except UserModel.MultipleObjectsReturned:
                log.error(
                    'Authentication with email=%r returned multiple users: %r',
                    email, UserModel.objects.filter(email=email))
            except UserModel.DoesNotExist:
                pass

            return user
