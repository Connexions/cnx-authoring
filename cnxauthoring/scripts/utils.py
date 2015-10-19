# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2014, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
"""Utility functions for commandline scripts"""
import os
import sys
from paste.deploy import appconfig


def parse_app_settings(config_uri, name='main'):
    """Parse the settings from the config file for the application.
    The application section defaults to name 'main'.
    """
    config_path = os.path.abspath(config_uri)
    return appconfig("config:{}".format(config_path), name=name)
