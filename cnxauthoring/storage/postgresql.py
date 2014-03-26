# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import psycopg2
import psycopg2.extras
from psycopg2 import Binary
from uuid import UUID
import json

from .main import BaseStorage
from ..models import Document, Resource, create_content, MEDIATYPES
from .database import SQL

psycopg2.extras.register_uuid()

class PostgresqlStorage(BaseStorage):
    """Utility for managing and interfacing with the the storage medium."""

    def __init__(self, db_connection_string=None):
        #initialize db
        self.conn = psycopg2.connect(db_connection_string)

    def get(self, type_=Document, **kwargs):
        """Retrieve ``Document`` objects from storage."""
        for obj in self.get_all(type_=type_, **kwargs):
            return obj

    def get_all(self, type_=Document, **kwargs):
        """Retrieve ``Document`` objects from storage."""
        # all kwargs are expected to match attributes of the stored Document.
        # We're trusting the names of the args to match table column names, but not
        # trusting the values
        
        cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        type_name = type_.__name__.lower()
        
        # if ID is not a well formed uuid, there's no need to even hit the db 
        if 'id' in kwargs and type(kwargs['id']) != UUID:
            try:
                kwargs['id'] = UUID(kwargs['id'])
            except ValueError:
                return

        match_clauses = ['{k} = %({k})s'.format(k = k) for k in  kwargs]
            
        cursor.execute(SQL['get'].format(tablename = type_name, where_clause = ' AND '.join(match_clauses)), kwargs)
        res = cursor.fetchall()
        if res:
            results = []
            for r in res:
                if 'license' in r:
                    r['license'] = eval(r['license'])
                    rd = dict(r)
                    if rd['media_type'] == MEDIATYPES['binder']:
                        rd['tree'] = json.loads(rd.pop('content'))
                    item = create_content(**rd)
                    results.append(item)
                else:
                    rd = dict(r)
                    rd.pop('hash')
                    results.append(type_(**dict(rd)))
                    
            for item in results:
                yield item
            

    def add(self, item_or_items):
        """Adds any item or set of items to storage."""
        if isinstance(item_or_items, list):
            raise NotImplementedError()
        item = item_or_items
        type_name= item.__class__.__name__.lower()
        cursor = self.conn.cursor()
        if type_name== 'resource':
            cursor.execute(SQL['add-resource'], 
                        {'hash':item._hash,'mediatype':item.mediatype,'data':Binary(item.data)})
        elif type_name in ['document','binder']:
            args = item.to_dict()
            args['license'] = repr(args['license'])
            args['media_type'] = MEDIATYPES[type_name]
            if 'tree' in args:
                    args['content'] = json.dumps(args.pop('tree'))
            cursor.execute(SQL['add-document'], args)
        else:
            raise NotImplementedError(type_name)
        return item

    def remove(self, item_or_items):
        """Removes any item or set of items from storage."""
        raise NotImplementedError()

    def update(self, item_or_items):
        """Updates any item or set of items in storage."""
        if isinstance(item_or_items, list):
            raise NotImplementedError()
        item = item_or_items
        type_name= item.__class__.__name__.lower()
        cursor = self.conn.cursor()
        if type_name== 'resource':
            cursor.execute(SQL['update-resource'], 
                        {'hash':item._hash,'mediatype':item.mediatype,'data':Binary(item.data)})
        elif type_name in ['document', 'binder']:
            args = item.to_dict()
            args['license'] = repr(args['license'])
            if 'tree' in args:
                args['content'] = json.dumps(args.pop('tree'))
            cursor.execute(SQL['update-document'], args)
        return item

    def persist(self):
        """Persist/commit the changes."""
        self.conn.commit()

    def search(self, limits, type_=Document, submitter=None):
        """Retrieve any ``Document`` objects from storage that matches the
        search terms."""
        if type_ != Document:
            raise NotImplementedError()

        cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        search_terms = []
        for limit_type, term in limits:
            if limit_type != 'text':
                raise NotImplementedError()
            search_terms.append(term.lower())

        title_terms = ['lower(title) ~ %s'] * len(search_terms)
        where_clause = '(' + ' OR '.join(title_terms) + ') AND submitter = %s'
        sqlargs = search_terms + [submitter]        

        cursor.execute(SQL['search-title'].format(where_clause=where_clause), sqlargs)
        res = cursor.fetchall()
        if res:
            results = []
            for item in res:
                if 'license' in item:
                    item['license'] = eval(item['license'])
                    results.append(create_content(**dict(item)))

            for item in results:
                yield item
