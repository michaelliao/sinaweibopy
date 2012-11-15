#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Michael Liao'

'''
A WSGI app for dev.
'''

from wsgiref.simple_server import make_server

import os, logging
logging.basicConfig(level=logging.INFO)

from transwarp import web, db

def create_app():
#    from conf import dbconf
#    kwargs = dict([(s, getattr(dbconf, s)) for s in dir(dbconf) if s.startswith('DB_')])
#    dbargs = kwargs.pop('DB_ARGS', {})
    db.init(db_type = 'mysql', db_schema = 'weibo', db_host = 'localhost', db_port = 3306, db_user = 'www-data', db_password = 'www-data')
    return web.WSGIApplication(('urls',), document_root=os.path.dirname(os.path.abspath(__file__)), template_engine='jinja2', DEBUG=True)

if __name__=='__main__':
    logging.info('application will start...')
    server = make_server('127.0.0.1', 8080, create_app())
    server.serve_forever()
