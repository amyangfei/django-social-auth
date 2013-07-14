"""
Renren OAuth support.

This adds support for Renren OAuth service. An application must
be registered first on renren.com and the settings RENREN_CONSUMER_KEY
and RENREN_CONSUMER_SECRET must be defined with they corresponding
values.

By default account id is stored in extra_data field, check OAuthBackend
class for details on how to extend it.
"""
from urllib import urlencode
from django.utils import simplejson

from social_auth.utils import dsa_urlopen
from social_auth.backends import ConsumerBasedOAuth, OAuthBackend, BaseOAuth2
from social_auth.exceptions import AuthCanceled


RENREN_SERVER = 'graph.renren.com'
RENREN_REQUEST_TOKEN_URL = 'https://%s/oauth/request_token' % \
                                RENREN_SERVER
RENREN_ACCESS_TOKEN_URL = 'https://%s/oauth/token' % \
                                RENREN_SERVER

RENREN_AUTHORIZATION_URL = 'https://%s/oauth/authorize' % \
                                RENREN_SERVER


class RenrenBackend(OAuthBackend):
    """Renren OAuth authentication backend"""
    name = 'renren'
    EXTRA_DATA = [('uid', 'id')]

    def get_user_id(self, details, response):
        return response['uid']

    def get_user_details(self, response):
        """Return user details from Renren"""
        return {'username': response.get("name", ""),
                'email': ''}

class RenrenAuth(BaseOAuth2):
    """Renren OAuth authentication mechanism"""
    AUTHORIZATION_URL = RENREN_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = RENREN_ACCESS_TOKEN_URL
    AUTH_BACKEND = RenrenBackend
    SETTINGS_KEY_NAME = 'RENREN_CONSUMER_KEY'
    SETTINGS_SECRET_NAME = 'RENREN_CONSUMER_SECRET'
    REDIRECT_STATE = False

    def user_data(self, access_token, *args, **kwargs):
        """Return user data provided"""
        uid = kwargs.get('response', {}).get('user').get('id')
        data = {'access_token': access_token, 'v':'1.0', 'uid': uid,'method':'users.getProfileInfo','format':'JSON'}
        url = 'https://api.renren.com/restserver.do'# + urlencode(data)
        try:
            return simplejson.loads(dsa_urlopen(url,urlencode(data)).read())
        except (Error, ValueError, KeyError, IOError):
            return None


# Backend definition
BACKENDS = {
    'renren': RenrenAuth
}
