# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###

from pyramid.events import NewRequest


def add_cors_headers(request, response):
    settings = request.registry.settings
    acac = settings['cors.access_control_allow_credentials']
    acao = settings['cors.access_control_allow_origin'].split()
    acah = settings['cors.access_control_allow_headers']
    acam = settings['cors.access_control_allow_methods']
    if acac:
        response.headerlist.append(
                ('Access-Control-Allow-Credentials', acac))
    if acao:
        if request.headers.get('Origin') in acao:
            response.headerlist.append(
                ('Access-Control-Allow-Origin', request.headers.get('Origin')))
        else:
            response.headerlist.append(
                ('Access-Control-Allow-Origin', acao[0]))
    if acah:
        response.headerlist.append(
                ('Access-Control-Allow-Headers', acah))
    if acam:
        response.headerlist.append(
                ('Access-Control-Allow-Methods', acam))


def new_request_subscriber(event):
    request = event.request
    request.add_response_callback(add_cors_headers)


def main(config):
    config.add_subscriber(new_request_subscriber, NewRequest)
