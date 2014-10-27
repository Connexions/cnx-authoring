# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
from openstax_accounts.interfaces import IOpenstaxAccountsAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator
from pyramid.security import Allow, Everyone, Authenticated
from pyramid.session import UnencryptedCookieSessionFactoryConfig


def declare_routes(config):
    """Declaration of routing"""
    add_route = config.add_route
    add_route('options', 
            '/{foo:(\*|search|contents|users|resources|login|callback|logout)/?.*}',
            request_method='OPTIONS')
    add_route('search-content', '/search', request_method='GET')
    add_route('get-content-json', '/contents/{id}@draft.json',
              request_method='GET')
    add_route('get-resource', '/resources/{hash}', request_method='GET')
    add_route('post-content', '/users/contents', request_method='POST')
    add_route('post-resource', '/resources', request_method='POST')
    add_route('put-content', '/contents/{id}@draft.json', request_method='PUT')
    add_route('delete-content', '/contents/{id}@draft.json',
              request_method='DELETE')
    add_route('delete-user-content',
              '/contents/{id}@draft/users/{user_id}.json',
              request_method='DELETE')
    add_route('user-search', '/users/search', request_method='GET')
    add_route('profile', '/users/profile', request_method='GET')
    add_route('user-contents', '/users/contents', request_method='GET')
    add_route('publish', '/publish', request_method='POST')
    add_route('acceptance-info', '/contents/{id}@draft/acceptance')

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

    config = Configurator(settings=settings,
                          session_factory=session_factory)
    declare_routes(config)
    declare_oauth_routes(config)

    # storage is configurable. module and class for a given storage name are
    # configured in storage __init__, settings for that storage are then
    # passed as keyword arguments (without the prefix) i.e.  configuration of
    # 'storage = pickle' with 'pickle.filename' values.  lookup storage
    # factory by name and pass in 'filename = foo'

    from . import storage

    
    storages = storage.storages
    storage_name = settings.get('storage',storage.default_storage)
    storage_modname, storage_class = storages[storage_name]
    storage_settings = {k.split('.')[1].replace('-','_'):settings[k] for k in settings if k.split('.')[0] == storage_name}
    storage_mod = __import__('.'.join((storage.__name__,storage_modname)), fromlist = [storage.__name__])
    storage_instance = getattr(storage_mod,storage_class)(**storage_settings)
    setattr(storage, 'storage', storage_instance)

    config.scan(ignore='cnxauthoring.tests')
    config.include('cnxauthoring.events.main')

    config.include('openstax_accounts.main')
    # authorization policy must be set if an authentication policy is set
    config.set_authentication_policy(
            config.registry.getUtility(IOpenstaxAccountsAuthenticationPolicy))
    config.set_authorization_policy(ACLAuthorizationPolicy())

    return config.make_wsgi_app()
