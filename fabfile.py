#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Michael Liao'

'''
Build release package.
'''

from fabric.api import *

_TAR_FILE = 'miniweibo.tar.gz'

def build():
    includes = ['static', 'transwarp', 'favicon.ico', 'index.wsgi', 'urls.py', 'weibo.py']
    excludes = ['.*', '*.pyc', '*.pyo', 'static/css/less/*']
    local('rm -f %s' % _TAR_FILE)
    cmd = ['tar', '--dereference', '-czvf', _TAR_FILE]
    for ex in excludes:
        cmd.append('--exclude=\'%s\'' % ex)
    cmd.extend(includes)
    local(' '.join(cmd))
