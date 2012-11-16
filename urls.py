#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Michael Liao'

import time, json, base64, logging, hashlib
from datetime import datetime, tzinfo, timedelta

from transwarp.web import ctx, get, post, route, seeother, forbidden, jsonresult, Template
from transwarp import db

from weibo import APIError, APIClient

_TD_ZERO = timedelta(0)
_TD_8 = timedelta(hours=8)

class UTC8(tzinfo):
    def utcoffset(self, dt):
        return _TD_8

    def tzname(self, dt):
        return "UTC+8:00"

    def dst(self, dt):
        return _TD_ZERO

_UTC8 = UTC8()

def _format_datetime(dt):
    t = datetime.strptime(dt, '%a %b %d %H:%M:%S +0800 %Y').replace(tzinfo=_UTC8)
    return time.mktime(t.timetuple())

def _format_user(u):
    return dict(id=str(u.id), screen_name=u.screen_name, profile_url=u.profile_url, verified=u.verified, verified_type=u.verified_type, profile_image_url=u.profile_image_url)

def _format_weibo(st):
    user = st.user
    r = dict(
        user = _format_user(st.user),
        text = st.text,
        created_at = _format_datetime(st.created_at),
        reposts_count = st.reposts_count,
        comments_count = st.comments_count,
    )
    if 'original_pic' in st:
        r['original_pic'] = st.original_pic
    if 'thumbnail_pic' in st:
        r['thumbnail_pic'] = st.thumbnail_pic
    if 'retweeted_status' in st:
        r['retweeted_status'] = _format_weibo(st.retweeted_status)
    return r

@get('/')
def index():
    u = _check_cookie()
    if u is None:
        return Template('static/signin.html')
    return Template('static/index.html', user=u)

@post('/update')
@jsonresult
def update():
    u = _check_cookie()
    if u is None:
        return dict(error='failed', redirect='/signin')
    client = _create_client()
    client.set_access_token(u.auth_token, u.expired_time)
    try:
        r = client.statuses.update.post(status=ctx.request['status'])
        if 'error' in r:
            return r
        return dict(result='success')
    except APIError, e:
        return dict(error='failed')

@route('/friends')
@jsonresult
def friends():
    u = _check_cookie()
    if u is None:
        return dict(error='failed', redirect='/signin')
    client = _create_client()
    client.set_access_token(u.auth_token, u.expired_time)
    try:
        r = client.friendships.friends.get(uid=u.id, count=99)
        return [_format_user(u) for u in r.users]
    except APIError, e:
        return dict(error='failed')

@route('/load')
@jsonresult
def load():
    u = _check_cookie()
    if u is None:
        return dict(error='failed', redirect='/signin')
    client = _create_client()
    client.set_access_token(u.auth_token, u.expired_time)
    try:
        r = client.statuses.home_timeline.get()
        return [_format_weibo(s) for s in r.statuses]
    except APIError, e:
        return dict(error='failed')

@post('/hint')
@jsonresult
def hint():
    u = _check_cookie()
    if u is None:
        return dict(error='failed', redirect='/signin')
    client = _create_client()
    client.set_access_token(u.auth_token, u.expired_time)
    try:
        return client.remind.unread_count.get()
    except APIError, e:
        return dict(error='failed')

@get('/signin')
def signin():
    client = _create_client()
    raise seeother(client.get_authorize_url())

@get('/signout')
def signout():
    ctx.response.set_cookie(_COOKIE, 'deleted', max_age=0)
    raise seeother('/')

@get('/callback')
def callback():
    i = ctx.request.input(code='')
    code = i.code
    client = _create_client()
    r = client.request_access_token(code)
    logging.info('access token: %s' % json.dumps(r))
    access_token, expires_in, uid = r.access_token, r.expires_in, r.uid
    client.set_access_token(access_token, expires_in)
    u = client.users.show.get(uid=uid)
    logging.info('got user: %s' % uid)
    users = db.select('select * from users where id=?', uid)
    user = dict(name=u.screen_name, \
            image_url=u.avatar_large or u.profile_image_url, \
            statuses_count=u.statuses_count, \
            friends_count=u.friends_count, \
            followers_count=u.followers_count, \
            verified=u.verified, \
            verified_type=u.verified_type, \
            auth_token=access_token, \
            expired_time=expires_in)
    if users:
        db.update_kw('users', 'id=?', uid, **user)
    else:
        user['id'] = uid
        db.insert('users', **user)
    _make_cookie(uid, access_token, expires_in)
    raise seeother('/')

_COOKIE = 'authuser'
_SALT = 'A random string'

def _make_cookie(uid, token, expires_in):
    expires = str(int(expires_in))
    s = '%s:%s:%s:%s' % (str(uid), str(token), expires, _SALT)
    md5 = hashlib.md5(s).hexdigest()
    cookie = '%s:%s:%s' % (str(uid), expires, md5)
    ctx.response.set_cookie(_COOKIE, base64.b64encode(cookie).replace('=', '_'), expires=expires_in)

def _check_cookie():
    try:
        b64cookie = ctx.request.cookies[_COOKIE]
        cookie = base64.b64decode(b64cookie.replace('_', '='))
        uid, expires, md5 = cookie.split(':', 2)
        if int(expires) < time.time():
            return
        L = db.select('select * from users where id=?', uid)
        if not L:
            return
        u = L[0]
        s = '%s:%s:%s:%s' % (uid, str(u.auth_token), expires, _SALT)
        if md5 != hashlib.md5(s).hexdigest():
            return
        return u
    except BaseException:
        pass

_APP_ID = ''
_APP_SECRET = ''
_ADMIN_PASS = 'admin'

@get('/admin')
def show_admin():
    return '''<html>
<body>
<form action="/admin" method="post">
<p>Input password:</p>
<p><input type="password" name="passwd" /></p>
</form>
</body>
</html>
'''

@post('/admin')
def do_admin():
    global _APP_ID, _APP_SECRET, _ADMIN_PASS

    i = ctx.request.input()
    if i.passwd != _ADMIN_PASS:
        raise forbidden()
    admin_pass = i.get('new_passwd', '')
    app_id = i.get('app_id', '')
    app_secret = i.get('app_secret', '')
    msg = ''
    if admin_pass and app_id and app_secret:
        db.update('delete from settings')
        db.update('insert into settings (id, value) values (?, ?)', 'app_id', app_id)
        db.update('insert into settings (id, value) values (?, ?)', 'app_secret', app_secret)
        db.update('insert into settings (id, value) values (?, ?)', 'admin_pass', admin_pass)
        msg = 'Updated!'
        _APP_ID = app_id
        _APP_SECRET = app_secret
        _ADMIN_PASS = admin_pass
    return '''<html>
<body>
<p>%s</p>
<form action="/admin" method="post">
<p>App ID:</p>
<p><input type="text" name="app_id" value="%s" /></p>
<p>App Secret:</p>
<p><input type="text" name="app_secret" value="%s" /></p>
<p>Old Password:</p>
<p><input type="text" name="passwd" readonly="readonly" value="%s" /></p>
<p>New Password:</p>
<p><input type="text" name="new_passwd" value="%s" /></p>
<p>WARNING: click submit will update app_id, app_secret and admin password!</p>
<p><input type="submit" name="submit" value="Submit" /></p>
</form>
</body>
</html>
''' % (msg, _APP_ID, _APP_SECRET, _ADMIN_PASS, _ADMIN_PASS)

def _load_app_info():
    global _APP_ID, _APP_SECRET, _ADMIN_PASS
    for s in db.select('select * from settings'):
        if s.id == 'app_id':
            _APP_ID = s.value
        if s.id == 'app_secret':
            _APP_SECRET = s.value
        if s.id == 'admin_pass':
            _ADMIN_PASS = s.value

def _create_client():
    return APIClient(_APP_ID, _APP_SECRET, 'http://sinaweibopy.sinaapp.com/callback')

_load_app_info()
