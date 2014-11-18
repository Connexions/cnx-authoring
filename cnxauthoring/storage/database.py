# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2014, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
"""Database models and utilities"""
import datetime
import os
import psycopg2
import re


CONNECTION_SETTINGS_KEY = 'postgresql.db-connection-string'

here = os.path.abspath(os.path.dirname(__file__))
SQL_DIRECTORY = os.path.join(here, 'sql')
DB_SCHEMA_DIRECTORY = os.path.join(SQL_DIRECTORY, 'schema')
DB_SCHEMA_FILES = (
    'document.sql',
    'resource.sql',
    'document-acl.sql',
    'document-licensor-acceptance.sql',
    )

DB_SCHEMA_FILE_PATHS = tuple([os.path.join(DB_SCHEMA_DIRECTORY, dsf)
                              for dsf in  DB_SCHEMA_FILES])

def _read_sql_file(name):
    path = os.path.join(SQL_DIRECTORY, '{}.sql'.format(name))
    with open(path, 'r') as fp:
        return fp.read()
SQL = {
    'get': _read_sql_file('get'),
    'get-document': _read_sql_file('get-document'),
    'add-document': _read_sql_file('add-document'),
    'add-document-acl': _read_sql_file('add-document-acl'),
    'add-document-licensor-acceptance': _read_sql_file('add-document-licensor-acceptance'),
    'add-resource': _read_sql_file('add-resource'),
    'delete-document': _read_sql_file('delete-document'),
    'delete-document-acl': _read_sql_file('delete-document-acl'),
    'delete-document-licensor-acceptance': _read_sql_file('delete-document-licensor-acceptance'),
    'delete-resource': _read_sql_file('delete-resource'),
    'update-document': _read_sql_file('update-document'),
    'update-resource': _read_sql_file('update-resource'),
    'search-title': _read_sql_file('search-title'),
    }


def initdb(settings, clear=False):
    """Initialize the database from the given settings. If clear is true, drop
       tables first.
    """
    with psycopg2.connect(settings[CONNECTION_SETTINGS_KEY]) as db_connection:
        if clear:
            with db_connection.cursor() as cursor:
                schema_drop = os.path.join(DB_SCHEMA_DIRECTORY, 'drop_all.sql')
                with open(schema_drop, 'r') as f:
                    cursor.execute(f.read())
        with db_connection.cursor() as cursor:
            for schema_filepath in DB_SCHEMA_FILE_PATHS:
                with open(schema_filepath, 'r') as f:
                    cursor.execute(f.read())
            sql_constants = [os.path.join(DB_SCHEMA_DIRECTORY, filename)
                             for filename in os.listdir(DB_SCHEMA_DIRECTORY)
                             if filename.startswith('constant-')]
            for filepath in sql_constants:
                with open(filepath, 'r') as f:
                    cursor.execute(f.read())
