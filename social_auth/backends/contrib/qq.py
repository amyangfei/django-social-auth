"""
QQ OAuth support.

This adds support for QQ OAuth service. An application must
be registered first on renren.com and the settings QQ_CONSUMER_KEY
and QQ_CONSUMER_SECRET must be defined with they corresponding
values.

By default account id is stored in extra_data field, check OAuthBackend
class for details on how to extend it.
"""
import urlparse
import re
from urllib2 import Request
from urllib import urlencode
from django.utils import simplejson
from social_auth.utils import dsa_urlopen

from social_auth.backends import ConsumerBasedOAuth, OAuthBackend, BaseOAuth2
from social_auth.exceptions import AuthCanceled
from social_auth.utils import setting


QQ_SERVER = 'graph.qq.com'
QQ_REQUEST_TOKEN_URL = 'https://%s/oauth2.0/request_token' % \
                                QQ_SERVER
QQ_ACCESS_TOKEN_URL = 'https://%s/oauth2.0/token' % \
                                QQ_SERVER

QQ_AUTHORIZATION_URL = 'https://%s/oauth2.0/authorize' % \
                                QQ_SERVER


class QqBackend(OAuthBackend):
    """QQ OAuth authentication backend"""
    name = 'qq'
    EXTRA_DATA = [('figureurl_qq_1', 'figureurl_qq_1'),('nickname', 'username'),('uid','uid')]

    def get_user_id(self, details, response):
        m = re.match(r'http:\/\/qzapp.qlogo.cn\/qzapp\/\d{9}/(?P<openid>\w{32})/\d{2}',response['figureurl_1'])
        result = m.groupdict()
        return result['openid']

    def get_user_details(self, response):
        """Return user details from QQ"""
        return {'username': response.get("nickname", ""),
                'email': ''}

class QqAuth(BaseOAuth2):
    """Renren OAuth authentication mechanism"""
    AUTHORIZATION_URL = QQ_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = QQ_ACCESS_TOKEN_URL
    AUTH_BACKEND = QqBackend
    SETTINGS_KEY_NAME = 'QQ_CLIENT_ID'
    SETTINGS_SECRET_NAME = 'QQ_CLIENT_SECRET'
    DEFAULT_SCOPE = setting('QQ_SCOPE')

    def get_open_id(self, access_token):
        data = {'access_token': access_token}
        url = 'https://graph.qq.com/oauth2.0/me?' + urlencode(data)
        res = dsa_urlopen(url).read()
        #obj = res.read()
        if res.find('callback') > -1:
             pos_lb = res.find('{')
             pos_rb = res.find('}')
             res = res[pos_lb:pos_rb+1]
             openid_dict = simplejson.loads(res,encoding='utf-8')
             openid = openid_dict['openid']
             return openid

    def user_data(self, access_token, *args, **kwargs):
        """Return user data provided"""
        openid = self.get_open_id(access_token)
        data = {'access_token': access_token, 'openid': openid,'format':'JSON','oauth_consumer_key':setting('QQ_CLIENT_ID')}
        url = 'https://graph.qq.com/user/get_simple_userinfo?' + urlencode(data)# + urlencode(data)
        try:
            return simplejson.loads(dsa_urlopen(url).read())
        except (Error, ValueError, KeyError, IOError):
            return None

    #qq return token use a str, so can not use json load to read the res
    def auth_complete(self, *args, **kwargs):
        """Completes loging process, must return user instance"""
        self.process_error(self.data)
        params = self.auth_complete_params(self.validate_state())
        request = Request(self.ACCESS_TOKEN_URL, data=urlencode(params),
                          headers=self.auth_headers())

        try:
            res = dsa_urlopen(request).read()
            response = urlparse.parse_qs(res)
            for key in response:
                response[key] = response[key][0]
        except HTTPError, e:
            if e.code == 400:
                raise AuthCanceled(self)
            else:
                raise
        except (ValueError, KeyError):
            raise AuthUnknownError(self)

        self.process_error(response)
        return self.do_auth(response['access_token'], response=response,
                            *args, **kwargs)


# Backend definition
BACKENDS = {
    'qq': QqAuth
}
