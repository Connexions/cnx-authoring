# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
from wsgiref.simple_server import make_server
from . import main

app = main({})
server = make_server('0.0.0.0', 8080, app)
server.serve_forever()
