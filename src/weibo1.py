#!/usr/bin/env python
# -*- coding: utf-8 -*-

__version__ = '1.0'
__author__ = 'Liao Xuefeng (askxuefeng@gmail.com)'

'''
Python client SDK for sina weibo API using OAuth 1.0
'''

try:
    import json
except ImportError:
    import simplejson as json
import time
import hmac
import uuid
import base64
import urllib
import urllib2
import hashlib
import logging

_OAUTH_SIGN_METHOD = 'HMAC-SHA1'
_OAUTH_VERSION = '1.0'

class OAuthToken(object):

    def __init__(self, oauth_token, oauth_token_secret, oauth_verifier=None, **kw):
        self.oauth_token = oauth_token
        self.oauth_token_secret = oauth_token_secret
        self.oauth_verifier = oauth_verifier
        for k, v in kw.iteritems():
            setattr(self, k, v)

    def __str__(self):
        attrs = [s for s in dir(self) if not s.startswith('__')]
        kvs = ['%s = %s' % (k, getattr(self, k)) for k in attrs]
        return ', '.join(kvs)

    __repr__ = __str__

class APIClient(object):
    def __init__(self, app_key, app_secret, token=None, callback=None, domain='api.t.sina.com.cn'):
        self.app_key = str(app_key)
        self.app_secret = str(app_secret)
        if token:
            if isinstance(token, OAuthToken):
                if token.oauth_token:
                    self.oauth_token = token.oauth_token
                if token.oauth_token_secret:
                    self.oauth_token_secret = token.oauth_token_secret
                if token.oauth_verifier:
                    self.oauth_verifier = token.oauth_verifier
            else:
                raise TypeError('token parameter must be instance of OAuthToken.')
        self.callback = callback
        self.api_url = 'http://%s' % domain
        self.get = HttpObject(self, _HTTP_GET)
        self.post = HttpObject(self, _HTTP_POST)

    def _oauth_request(self, method, url, **kw):
        params = dict( \
                oauth_consumer_key=self.app_key, \
                oauth_nonce=_generate_nonce(), \
                oauth_signature_method=_OAUTH_SIGN_METHOD, \
                oauth_timestamp=str(int(time.time())), \
                oauth_version=_OAUTH_VERSION, \
                oauth_token=self.oauth_token)
        params.update(kw)
        m = 'GET' if method==_HTTP_GET else 'POST'
        bs = _generate_base_string(m, url, **params)
        key = '%s&%s' % (self.app_secret, self.oauth_token_secret)
        oauth_signature = _generate_signature(key, bs)
        print 'params:', params
        print 'base string:', bs
        print 'key:', key, 'sign:', oauth_signature
        print 'url:', url
        r = _http_call(url, method, self.__build_oauth_header(params, oauth_signature=oauth_signature), **kw)
        return r

    def get_request_token(self):
        '''
        Step 1: request oauth token.
        Returns:
          OAuthToken object contains oauth_token and oauth_token_secret
        '''
        params = dict(oauth_callback=self.callback, \
                oauth_consumer_key=self.app_key, \
                oauth_nonce=_generate_nonce(), \
                oauth_signature_method=_OAUTH_SIGN_METHOD, \
                oauth_timestamp=str(int(time.time())), \
                oauth_version=_OAUTH_VERSION)
        url = '%s/oauth/request_token' % self.api_url
        bs = _generate_base_string('GET', url, **params)
        params['oauth_signature'] = base64.b64encode(hmac.new('%s&' % self.app_secret, bs, hashlib.sha1).digest())
        r = _http_call(url, _HTTP_GET, return_json=False, **params)
        kw = _parse_params(r, False)
        return OAuthToken(**kw)

    def get_authorize_url(self, oauth_token):
        '''
        Step 2: get authorize url and redirect to it.
        Args:
          oauth_token: oauth_token str that returned from request_token:
                       oauth_token = client.request_token().oauth_token
        Returns:
          redirect url, e.g. "http://api.t.sina.com.cn/oauth/authorize?oauth_token=ABCD1234XYZ"
        '''
        return '%s/oauth/authorize?oauth_token=%s' % (self.api_url, oauth_token)

    def get_access_token(self):
        '''
        get access token from request token:
        request_token = OAuthToken(oauth_token, oauth_secret, oauth_verifier)
        client = APIClient(appkey, appsecret, request_token)
        access_token = client.get_access_token()
        '''
        params = {
            'oauth_consumer_key': self.app_key,
            'oauth_timestamp': str(int(time.time())),
            'oauth_nonce': _generate_nonce(),
            'oauth_version': _OAUTH_VERSION,
            'oauth_signature_method': _OAUTH_SIGN_METHOD,
            'oauth_token': self.oauth_token,
            'oauth_verifier': self.oauth_verifier,
        }
        url = '%s/oauth/access_token' % self.api_url
        bs = _generate_base_string('GET', url, **params)
        key = '%s&%s' % (self.app_secret, self.oauth_token_secret)
        oauth_signature = _generate_signature(key, bs)
        authorization = self.__build_oauth_header(params, oauth_signature=oauth_signature)
        r = _http_call(url, _HTTP_GET, authorization, return_json=False)
        kw = _parse_params(r, False)
        return OAuthToken(**kw)

    def __build_oauth_header(self, params, **kw):
        '''
        build oauth header like: Authorization: OAuth oauth_token="xxx", oauth_nonce="123"
        Args:
          params: parameter dict.
          **kw: any additional key-value parameters.
        '''
        d = dict(**kw)
        d.update(params)
        L = [r'%s="%s"' % (k, v) for k, v in d.iteritems() if k.startswith('oauth_')]
        return 'OAuth %s' % ', '.join(L)

    def __getattr__(self, attr):
        ' a shortcut for client.get.funcall() to client.funcall() '
        return getattr(self.get, attr)

def _obj_hook(pairs):
    '''
    convert json object to python object.
    '''
    o = JsonObject()
    for k, v in pairs.iteritems():
        o[str(k)] = v
    return o

class APIError(StandardError):
    '''
    raise APIError if got failed json message.
    '''
    def __init__(self, error_code, error, request):
        self.error_code = error_code
        self.error = error
        self.request = request
        StandardError.__init__(self, error)

    def __str__(self):
        return 'APIError: %s: %s, request: %s' % (self.error_code, self.error, self.request)

class JsonObject(dict):
    '''
    general json object that can bind any fields but also act as a dict.
    '''
    def __getattr__(self, attr):
        return self[attr]

    def __setattr__(self, attr, value):
        self[attr] = value

def _encode_multipart(**kw):
    '''
    Build a multipart/form-data body with generated random boundary.
    '''
    boundary = '----------%s' % hex(int(time.time() * 1000))
    data = []
    for k, v in kw.iteritems():
        data.append('--%s' % boundary)
        if hasattr(v, 'read'):
            # file-like object:
            ext = ''
            filename = getattr(v, 'name', '')
            n = filename.rfind('.')
            if n != (-1):
                ext = filename[n:].lower()
            content = v.read()
            data.append('Content-Disposition: form-data; name="%s"; filename="hidden"' % k)
            data.append('Content-Length: %d' % len(content))
            data.append('Content-Type: %s\r\n' % _guess_content_type(ext))
            data.append(content)
        else:
            data.append('Content-Disposition: form-data; name="%s"\r\n' % k)
            data.append(v.encode('utf-8') if isinstance(v, unicode) else v)
    data.append('--%s--\r\n' % boundary)
    return '\r\n'.join(data), boundary

_CONTENT_TYPES = { '.png': 'image/png', '.gif': 'image/gif', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.jpe': 'image/jpeg' }

def _guess_content_type(ext):
    return _CONTENT_TYPES.get(ext, 'application/octet-stream')

_HTTP_GET = 0
_HTTP_POST = 1
_HTTP_UPLOAD = 2

def _http_call(url, method, authorization=None, return_json=True, **kw):
    '''
    send an http request and return headers and body if no error.
    '''
    params = None
    boundary = None
    if method==_HTTP_UPLOAD:
        params, boundary = _encode_multipart(**kw)
    else:
        params = _encode_params(**kw)
    http_url = '%s?%s' % (url, params) if method==_HTTP_GET and params else url
    http_body = None if method==_HTTP_GET else params
    req = urllib2.Request(http_url, data=http_body)
    if authorization:
        print 'Authorization:', authorization
        req.add_header('Authorization', authorization)
    if boundary:
        req.add_header('Content-Type', 'multipart/form-data; boundary=%s' % boundary)
    print method, http_url, 'BODY:', http_body
    resp = urllib2.urlopen(req)
    body = resp.read()
    if return_json:
        r = json.loads(body, object_hook=_obj_hook)
        if hasattr(r, 'error_code'):
            raise APIError(r.error_code, getattr(r, 'error', ''), getattr(r, 'request', ''))
        return r
    return body

class HttpObject(object):

    def __init__(self, client, method):
        self.client = client
        self.method = method

    def __getattr__(self, attr):
        def wrap(**kw):
            return self.client._oauth_request(self.method, '%s/%s.json' % (self.client.api_url, attr.replace('__', '/')), **kw)
        return wrap

################################################################################
# utility functions
################################################################################

def _parse_params(params_str, unicode_value=True):
    '''
    parse a query string as JsonObject (also a dict)
    Args:
        params_str: query string as str.
        unicode_value: return unicode value if True, otherwise str value. default true.
    Returns:
        JsonObject (inherited from dict)
    
    >>> s = _parse_params('a=123&b=X%26Y&c=%E4%B8%AD%E6%96%87')
    >>> s.a
    u'123'
    >>> s.b
    u'X&Y'
    >>> s.c==u'\u4e2d\u6587'
    True
    >>> s = _parse_params('a=123&b=X%26Y&c=%E4%B8%AD%E6%96%87', False)
    >>> s.a
    '123'
    >>> s.b
    'X&Y'
    >>> s.c=='\xe4\xb8\xad\xe6\x96\x87'
    True
    >>> s.d #doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    KeyError:
    '''
    d = dict()
    for s in params_str.split('&'):
        n = s.find('=')
        if n>0:
            key = s[:n]
            value = urllib.unquote(s[n+1:])
            d[key] = value.decode('utf-8') if unicode_value else value
    return JsonObject(**d)

def _encode_params(**kw):
    '''
    Encode parameters.
    '''
    if kw:
        args = []
        for k, v in kw.iteritems():
            qv = v.encode('utf-8') if isinstance(v, unicode) else str(v)
            args.append('%s=%s' % (k, _quote(qv)))
        return '&'.join(args)
    return ''

def _quote(s):
    '''
    quote everything including /
    
    >>> _quote(123)
    '123'
    >>> _quote(u'\u4e2d\u6587')
    '%E4%B8%AD%E6%96%87'
    >>> _quote('/?abc=def& _+%')
    '%2F%3Fabc%3Ddef%26%20_%2B%25'
    '''
    if isinstance(s, unicode):
        s = s.encode('utf-8')
    return urllib.quote(str(s), safe='')

def _generate_nonce():
    ' generate random uuid as oauth_nonce '
    return uuid.uuid4().hex

def _generate_signature(key, base_string):
    '''
    generate url-encoded oauth_signature with HMAC-SHA1
    '''
    return _quote(base64.b64encode(hmac.new(key, base_string, hashlib.sha1).digest()))

def _generate_base_string(method, url, **params):
    '''
    generate base string for signature
    
    >>> method = 'GET'
    >>> url = 'http://www.sina.com.cn/news'
    >>> params = dict(a=1, b='A&B')
    >>> _generate_base_string(method, url, **params)
    'GET&http%3A%2F%2Fwww.sina.com.cn%2Fnews&a%3D1%26b%3DA%2526B'
    '''
    plist = [(_quote(k), _quote(v)) for k, v in params.iteritems()]
    plist.sort()
    return '%s&%s&%s' % (method, _quote(url), _quote('&'.join(['%s=%s' % (k, v) for k, v in plist])))

if __name__=='__main__':
    import doctest
    doctest.testmod()
