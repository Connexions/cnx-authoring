# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2014, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
"""Commandline script used to initialize the SQL database."""
import os
import sys
import argparse

import psycopg2
from ..storage.database import CONNECTION_SETTINGS_KEY, initdb
from .utils import parse_app_settings

# FIXME These locations are also 'constants' in the tests module.
#       The tests module needs refactored before we can import from there.
here = os.path.abspath(os.path.dirname(__file__))
TEST_DATA_DIRECTORY = os.path.join(here, '..', 'tests', 'test_storage')
TESTING_DATA_SQL_FILE = os.path.join(TEST_DATA_DIRECTORY, 'data.sql')
EXAMPLE_DATA_FILEPATHS = (
    TESTING_DATA_SQL_FILE,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config_uri', help="Configuration INI file.")
#    parser.add_argument('--with-example-data', action='store_true',
#                        help="Initializes the database with example data.")
    args = parser.parse_args(argv)

    settings = parse_app_settings(args.config_uri)
    initdb(settings)

#    if args.with_example_data:
#        connection_string = settings[CONNECTION_SETTINGS_KEY]
#        with psycopg2.connect(connection_string) as db_connection:
#            with db_connection.cursor() as cursor:
#                for filepath in EXAMPLE_DATA_FILEPATHS:
#                    with open(filepath, 'r') as fb:
#                        cursor.execute(fb.read())
    return 0

if __name__ == '__main__':
    main()
