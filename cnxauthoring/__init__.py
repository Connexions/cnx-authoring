# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator
from pyramid.security import Allow, Everyone, Authenticated
from pyramid.session import UnencryptedCookieSessionFactoryConfig


class Site(object):
    __name__ = 'Pyramid root resource'
    __parent__ = None
    __acl__ = [
            (Allow, Authenticated, 'protected'),
            (Allow, Everyone, 'view'),
            ]

    def __init__(self, request):
        self.request = request


def declare_routes(config):
    """Declaration of routing"""
    add_route = config.add_route
    add_route('search-content', '/search', request_method='GET')
    add_route('get-content-json', '/contents/{id}@draft.json', request_method='GET')
    add_route('get-resource', '/resources/{hash}', request_method='GET')
    add_route('post-content', '/contents', request_method='POST')
    add_route('post-resource', '/resources', request_method='POST')
    add_route('put-content', '/contents/{id}@draft.json', request_method='PUT')
    add_route('user-search', '/users/search', request_method='GET')
    add_route('profile', '/users/profile', request_method='GET')
    add_route('user-contents', '/contents', request_method='GET')


def declare_oauth_routes(config):
    """Declaration of routing for oauth"""
    add_route = config.add_route
    add_route('login', '/login', request_method='GET')
    add_route('callback', '/callback', request_method='GET')
    add_route('logout', '/logout', request_method='GET')


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    # use a uuid4 string as the secret for the session factory
    session_factory = UnencryptedCookieSessionFactoryConfig(
            '311978f8-7af1-4b16-92fe-4c480cdda657')

    config = Configurator(settings=settings, root_factory=Site,
                          session_factory=session_factory)
    declare_routes(config)
    declare_oauth_routes(config)

    # XXX This is not ideal.
    #     Storage usage based on configuration would be best.
    #     Configuration of 'storage = mongodb' with 'mongodb.*' values.
    #     Lookup storage factory by name and pass in '<name>.*' values,
    #     where '*' would be a keyword argument..
    from . import storage
    from .storage.pickle_storage import PickleStorage
    storage_instance = PickleStorage(settings['pickle.filename'])
    setattr(storage, 'storage', storage_instance)

    config.scan(ignore='cnxauthoring.tests')
    config.include('cnxauthoring.events.main')

    config.include('openstax_accounts.openstax_accounts.main')
    config.include('openstax_accounts.authentication_policy.main')
    # authorization policy must be set if an authentication policy is set
    config.set_authorization_policy(ACLAuthorizationPolicy())

    return config.make_wsgi_app()
