# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
from pyramid.config import Configurator


__version__ = '0.1'


def declare_routes(config):
    """Declaration of routing"""
    add_route = config.add_route
    add_route('get-content', '/contents/{id}', request_method='GET')
    add_route('get-resource', '/resources/{hash}', request_method='GET')
    add_route('post-content', '/contents', request_method='POST')
    add_route('post-resource', '/resources', request_method='POST')


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    declare_routes(config)

    # XXX This is not ideal.
    #     Storage usage based on configuration would be best.
    #     Configuration of 'storage = mongodb' with 'mongodb.*' values.
    #     Lookup storage factory by name and pass in '<name>.*' values,
    #     where '*' would be a keyword argument..
    from . import storage
    from .storage.mongodb import MongoDBStorage
    storage_instance = MongoDBStorage(settings['mongodb.connection_uri'],
                                      settings['mongodb.database_name'])
    setattr(storage, 'storage', storage_instance)

    config.scan()
    return config.make_wsgi_app()
