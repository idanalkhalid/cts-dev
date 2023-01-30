# -*- coding: utf-8 -*-
# -----------------------------------------------------------------
# Name:         auth
# Purpose:      Controls authentication
#
# Author:       ThreatPipes
#
# Created:      23/07/2019
# Copyright:    (c) ThreatPipes 2019
# License:      GPL
# -----------------------------------------------------------------
import string
import random
import logging

import cherrypy
import bcrypt
import logging
from mako.template import Template
from mako.lookup import TemplateLookup

from cts import SpiderFootDb

from key import check_key

SESSION_KEY = '_cp_username'
ROLE_KEY = '_cp_role'
lookup = TemplateLookup(directories=[''])
docroot = ''
log = logging.getLogger(f"spiderfoot.{__name__}")


# Update last active time
def last_active():
    sess = cherrypy.session
    username = sess.get(SESSION_KEY, None)
    if username:
        dbh = SpiderFootDb(cherrypy.config['config_db'])
        dbh.userInstanceUpdateLastActive(username)


cherrypy.tools.last_active = cherrypy.Tool('before_handler', last_active)


# Check if there is at least one user
def count_users():
    dbh = SpiderFootDb(cherrypy.config['config_db'])
    users_count = dbh.userInstancesCount()[0][0]
    return users_count


def auth_error(message):
    templ = Template(filename='dyn/error.tmpl', lookup=lookup)
    return templ.render(message=message, docroot=docroot, version='0.1')


def least_one_user():
    register_path = '/auth/register'
    users_count = count_users()
    if users_count == 0 and cherrypy.serving.request.path_info != register_path and 'static' not in cherrypy.serving.request.path_info:
        raise cherrypy.HTTPRedirect(register_path)


cherrypy.tools.least_one_user = cherrypy.Tool('before_handler', least_one_user)


def check_credentials(username, password):
    """Verifies credentials for username and password.
    Returns None on success or a string describing the error on failure"""

    dbh = SpiderFootDb(cherrypy.config['config_db'])
    instance = dbh.userInstanceGet(username)

    if instance:
        salt = instance[6]
        password = password.encode('utf-8')
        hashpass = bcrypt.hashpw(password, salt)
        if instance[2] != hashpass:
            return ['Incorrect username or password.', '']
        log.info(hashpass)
        return ['', instance[3]]
    else:
        return ['Incorrect username or password.', '']


def check_auth(*args, **kwargs):
    """A tool that looks in config for 'auth.require'. If found and it
    is not None, a login is required and the entry is evaluated as a list of
    conditions that the user must fulfill"""
    conditions = cherrypy.request.config.get('auth.require', None)
    if conditions is not None:
        username = cherrypy.session.get(SESSION_KEY)
        if username:
            cherrypy.request.login = username
            for condition in conditions:
                if not condition():
                    raise cherrypy.HTTPRedirect("/auth/login")
        else:
            if cherrypy.config['environment'] != 'production':
                cherrypy.session[SESSION_KEY] = cherrypy.request.login = 'debug_user'
            else:
                raise cherrypy.HTTPRedirect("/auth/login")


cherrypy.tools.auth = cherrypy.Tool('before_handler', check_auth)


def require(*conditions):
    """A decorator that appends conditions to the auth.require config
    variable."""
    def decorate(f):
        if not hasattr(f, '_cp_config'):
            f._cp_config = dict()
        if 'auth.require' not in f._cp_config:
            f._cp_config['auth.require'] = []
        f._cp_config['auth.require'].extend(conditions)
        return f
    return decorate


def member_of(groupname):
    def check():
        # replace with actual check if <username> is in <groupname>
        return cherrypy.request.login == 'joe' and groupname == 'admin'
    return check


def name_is(reqd_username):
    return lambda: reqd_username == cherrypy.request.login


def any_of(*conditions):
    """Returns True if any of the conditions match"""
    def check():
        for c in conditions:
            if c():
                return True
        return False
    return check


def all_of(*conditions):
    """Returns True if all of the conditions match"""
    def check():
        for c in conditions:
            if not c():
                return False
        return True
    return check


# Controller to provide login and logout actions
class AuthController(object):

    @cherrypy.expose
    def register(self, from_page='/', **kwargs):
        templ = Template(filename='cts/auth/register.tmpl', lookup=lookup)

        users_count = count_users()
        # if users_count != 0:
        #    raise cherrypy.HTTPRedirect(from_page or "/")

        if cherrypy.request.method == 'POST':

            username = kwargs.get('username', None)
            password = kwargs.get('password', None)

            if username == '' or password == '':
                msg = 'Fill in the fields'
                return templ.render(pageid='REGISTER', from_page=from_page, msg=msg, docroot=docroot)

            dbh = SpiderFootDb(cherrypy.config['config_db'])

            users = dbh.userInstances()

            for user in users:
                if user[1] == username:
                    msg = 'Username already exists'
                    return templ.render(pageid='REGISTER', from_page=from_page, msg=msg, docroot=docroot)

            salt = bcrypt.gensalt()
            hashpass = bcrypt.hashpw(password.encode('utf8'), salt)

            dbh.userInstanceCreate(username, hashpass, salt, 'admin')

            raise cherrypy.HTTPRedirect(from_page or "/")

        else:
            msg = 'You need to create a member user account to get started. Additional users can be added later.'
            return templ.render(pageid='REGISTER', from_page='/', msg=msg, docroot=docroot)

        error_msg = check_credentials(username, password)
        if error_msg:
            return templ.render(pageid='LOGIN', title=title, from_page=from_page, msg=error_msg, docroot=docroot)
        else:
            cherrypy.session[SESSION_KEY] = cherrypy.request.login = username
            raise cherrypy.HTTPRedirect(from_page or "/")

    @cherrypy.expose
    def login(self, username=None, password=None, from_page="/"):
        templ = Template(filename='cts/auth/login.tmpl', lookup=lookup)
        title = 'Login'
        if username is None or password is None:
            msg = 'Enter login information. Please contact your CTS administrator if you need an account.'
            return templ.render(pageid='LOGIN', title=title, from_page=from_page, msg=msg, docroot=docroot)

        user = check_credentials(username, password)
        log.warning(user)
        if user[0]:
            return templ.render(pageid='LOGIN', title=title, from_page=from_page, msg=user[0], docroot=docroot)
        else:
            cherrypy.session[SESSION_KEY] = cherrypy.request.login = username
            cherrypy.session[ROLE_KEY] = cherrypy.request.login = user[1]
            raise cherrypy.HTTPRedirect(from_page or "/dashboard")

    @require()
    @cherrypy.expose
    def logout(self, from_page="/"):
        sess = cherrypy.session
        username = sess.get(SESSION_KEY, None)
        sess[SESSION_KEY] = None
        if username:
            cherrypy.request.login = None
        raise cherrypy.HTTPRedirect(from_page or "/")

    # User creation
    @require()
    @cherrypy.expose
    def createuser(self, *args, **kwargs):
        templ = Template(
            filename='cts/templates/usermanagement.tmpl', lookup=lookup)
        dbh = SpiderFootDb(cherrypy.config['config_db'])

        username = kwargs.get('username', None)
        password = kwargs.get('password', None)
        role = kwargs.get('role', None)

        if username == '' or password == '' or role == '':
            return auth_error('Fill in the fields')

        users = dbh.userInstances()

        for user in users:
            if user[1] == username:
                return auth_error('Username already exists')

        salt = bcrypt.gensalt()
        hashpass = bcrypt.hashpw(password.encode('utf8'), salt)

        dbh.userInstanceCreate(username, hashpass, salt, role)

        raise cherrypy.HTTPRedirect('/usermanagement')

    # User deletion

    @require()
    @cherrypy.expose
    def deleteuser(self, *args, **kwargs):
        user_id = kwargs.get('id', None)
        if user_id:
            dbh = SpiderFootDb(cherrypy.config['config_db'])
            dbh.userInstanceDelete(user_id)

        raise cherrypy.HTTPRedirect('/usermanagement')

    # User change password
    @require()
    @cherrypy.expose
    def userprofile(self, *args, **kwargs):
        dbh = SpiderFootDb(cherrypy.config['config_db'])
        sess = cherrypy.session
        username = sess.get(SESSION_KEY, None)
        api_key = dbh.userInstanceGet(username)[4]

        try:
            db_config = dbh.configGet()
            key_check = check_key(db_config['_lickey'])
        except:
            key_check = None

        if key_check == 'Not extended':
            need_license = 'not extended'
        elif key_check == 'Activated':
            need_license = None
        else:
            need_license = 'no license'

        if cherrypy.request.method == 'POST':
            password = kwargs.get('password', None)
            password_2 = kwargs.get('password_2', None)

            if username and password == password_2 and password != '' and password_2 != '':
                salt = bcrypt.gensalt()
                hashpass = bcrypt.hashpw(password.encode('utf8'), salt)
                dbh.userInstancePasswordUpdate(username, hashpass, salt)
                raise cherrypy.HTTPRedirect('/')
            elif password == '' or password_2 == '':
                msg = 'Fill in the fields'
                templ = Template(
                    filename='dyn/userprofile.tmpl', lookup=lookup)
                return templ.render(pageid='USERPROFILE', docroot=docroot, msg=msg, version=cherrypy.config['config_db']['__version'],
                                    api_key=api_key, need_license=need_license)
            elif password != password_2:
                msg = 'Passwords did not match'
                templ = Template(
                    filename='dyn/userprofile.tmpl', lookup=lookup)
                return templ.render(pageid='USERPROFILE', docroot=docroot, msg=msg, version=cherrypy.config['config_db']['__version'],
                                    api_key=api_key, need_license=need_license)
            else:
                raise cherrypy.HTTPRedirect('/auth/userprofile')
        else:
            templ = Template(filename='dyn/userprofile.tmpl', lookup=lookup)
            return templ.render(pageid='USERPROFILE', docroot=docroot, msg='', version=cherrypy.config['config_db']['__version'],
                                api_key=api_key, need_license=need_license)

    # User change password
    @require()
    @cherrypy.expose
    def apikeyrecreate(self, *args, **kwargs):
        dbh = SpiderFootDb(cherrypy.config['config_db'])
        sess = cherrypy.session
        username = sess.get(SESSION_KEY, None)
        lettersAndDigits = string.ascii_letters + string.digits
        api_key = ''.join(random.choice(lettersAndDigits) for i in range(20))
        dbh.userInstanceApiKeyUpdate(username, api_key)
        raise cherrypy.HTTPRedirect('/auth/userprofile')
