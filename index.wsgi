#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# index.wsgi for Sina AppEngine
#

__author__ = 'Michael Liao'

import os

import sae

from transwarp import web, db

def create_app():
    db.init(db_type = 'mysql', \
        db_schema = sae.const.MYSQL_DB, \
        db_host = sae.const.MYSQL_HOST, \
        db_port = int(sae.const.MYSQL_PORT), \
        db_user = sae.const.MYSQL_USER, \
        db_password = sae.const.MYSQL_PASS, \
        use_unicode = True, \
        charset = 'utf8')
    return web.WSGIApplication(('urls',), document_root=os.path.dirname(os.path.abspath(__file__)), template_engine='jinja2')

application = sae.create_wsgi_app(create_app())
