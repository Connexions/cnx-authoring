# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import io
import json
from uuid import UUID

import psycopg2
import psycopg2.extras
from psycopg2 import Binary
from psycopg2.extensions import STATUS_READY

from .main import BaseStorage
from ..models import Document, Resource, create_content, MEDIATYPES
from .database import SQL


psycopg2.extras.register_uuid()
psycopg2.extensions.register_adapter(dict, psycopg2.extras.Json)

JSON_FIELDS = ('authors', 'publishers', 'copyright_holders', 'editors',
               'translators', 'illustrators',)


# cribbed from http://stackoverflow.com/questions/19048017/python-extract-substitution-vars-from-format-string
def get_format_keys(s):
    d = {}
    while True:
        try:
            s % d
        except KeyError as exc:
            # exc.args[0] contains the name of the key that was not found;
            # 0 is used because it appears to work with all types of placeholders.
            d[exc.args[0]] = 0
        else:
            break
    return d.keys()


def check_args(s, kwargs):
    format_keys = get_format_keys(s)
    for k in kwargs:
        if k not in format_keys:
            raise KeyError(k)


def checked_execute(cur, s, kwargs):
    check_args(s, kwargs)
    cur.execute(s, kwargs)


class PostgresqlStorage(BaseStorage):
    """Utility for managing and interfacing with the the storage medium."""

    Error = psycopg2.Error

    def __init__(self, db_connection_string=None):
        #initialize db
        self.conn = psycopg2.connect(db_connection_string)

    def get(self, type_=Document, **kwargs):
        """Retrieve ``Document`` objects from storage."""
        for obj in self.get_all(type_=type_, **kwargs):
            return obj

    def _reassemble_model_from_document_entry(self, **row):
        """Reassembles a document ``row`` (in dictionary result format)
        into model object.
        """
        cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # FIXME media-type is called 'media_type' in a document/binder query
        #       and 'mediatype' in a resource query.
        #       If this is fixed this will read better at the very least.
        #       The fix should be rename the resources field to mediatype.
        #       This can then be fixed to something like:
        ## if row['mediatype'] in MEDIATTYPES.values(): 
        ##     # then process as a Document/Binder.
        ## else:
        ##     # then process as a Resource.
        if 'mediatype' in row:  # It's a resource...
            model = Resource(row['mediatype'], io.BytesIO(row['data'][:]),
                             filename=row['hash'])
        else:  # It's a Document/Binder...
            row['license'] = eval(row['license'])
            for field in ('user_id', 'permission', 'uuid'):
                if field in row:
                    row.pop(field)
            if row['media_type'] == MEDIATYPES['binder']:
                row['tree'] = json.loads(row.pop('content'))
            # BBB 05-Jan-2015 licensors - deprecated property 'licensors'
            #     needs changed in webview and archive before removing here.
            row['licensors'] = row['copyright_holders']
            # /BBB
            model = create_content(**row)

            # Attach ACL and license acceptance info.
            checked_execute(cursor, SQL['get'].format(
                tablename='document_acl',
                where_clause='uuid = %(uuid)s'), {'uuid': row['id']})
            permissions_by_users = {}
            for acl in cursor.fetchall():
                permissions_by_users.setdefault(acl['user_id'], [])
                permissions_by_users[acl['user_id']].append(
                        acl['permission'])
            #UNION with  the users' permissions on any containing draft binders
            binders = model.metadata['contained_in']
            if binders and binders != []:
                for binderid in binders:
                    checked_execute(cursor, SQL['get'].format(
                        tablename='document_acl',
                        where_clause='uuid = %(uuid)s'), {'uuid': binderid})
                    for acl in cursor.fetchall():
                        permissions_by_users.setdefault(acl['user_id'], [])
                        if acl['permission'] not in permissions_by_users[acl['user_id']]:
                            permissions_by_users[acl['user_id']].append(acl['permission'])

            for user_id, permissions in permissions_by_users.items():
                model.acls[user_id] = tuple(set(permissions))

            checked_execute(cursor, SQL['get'].format(
                tablename='document_licensor_acceptance',
                where_clause='uuid = %(uuid)s'), {'uuid': row['id']})
            licensor_acceptance = [
                {'id': r['user_id'], 'has_accepted': r['has_accepted']}
                for r in cursor.fetchall()]
            model.licensor_acceptance = licensor_acceptance
        return model

    def get_all(self, type_=Document, user_id=None, permissions=None,
                **kwargs):
        """Retrieve ``Document`` objects from storage."""
        # all kwargs are expected to match attributes of the stored Document.
        # We're trusting the names of the args to match table column names, but not
        # trusting the values

        in_progress = ( self.conn.status != STATUS_READY )

        cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        type_name = type_.__name__.lower()

        # if ID is not a well formed uuid, there's no need to even hit the db
        if 'id' in kwargs and type(kwargs['id']) != UUID:
            try:
                kwargs['id'] = UUID(kwargs['id'])
            except ValueError:
                return

        match_clauses = []
        match_values = kwargs.copy()
        for k, v in kwargs.items():
            if isinstance(v, dict):
                for json_k, json_v in v.items():
                    match_clauses.append(
                            "{field}->>'{json_key}' = %({field}_{json_key})s"
                            .format(field=k, json_key=json_k))
                    match_values['{field}_{json_key}'.format(
                        field=k, json_key=json_k)] = json_v
                match_values.pop(k)
            elif k == 'contained_in': # Array based storage , assumes singular key
                if v.startswith('not:'):
                    match_clauses.append(' NOT %(contained_in)s = ANY (contained_in) ')
                    match_values[k] = v[4:]
                else:
                    match_clauses.append(' %(contained_in)s = ANY (contained_in) ')
            else:
                if  str(v).startswith('not:'):
                    match_clauses.append(' NOT {field} = %({field})s'.format(field=k))
                    match_values[k] = str(v)[4:]
                else:
                    match_clauses.append('{field} = %({field})s'.format(field=k))

        # 1 = 1 in case where clause is empty
        where_clause = ' AND '.join(match_clauses) or '1 = 1'
        if type_name in ('document', 'binder') and user_id and permissions:
            match_values.update({
                'user_id': user_id,
                'permissions': permissions})
            checked_execute(cursor, SQL['get-document'].format(
                where_clause=where_clause), match_values)
        else:
            checked_execute(cursor, SQL['get'].format(
                tablename=type_name, where_clause=where_clause), match_values)
        res = cursor.fetchall()
        if not in_progress:
            self.conn.rollback() # Frees the connection
        if res:
            for r in res:
                yield self._reassemble_model_from_document_entry(**r)
        raise StopIteration

    def add(self, item_or_items):
        """Adds any item or set of items to storage."""
        if isinstance(item_or_items, list):
            raise NotImplementedError()
        item = item_or_items
        type_name= item.__class__.__name__.lower()
        cursor = self.conn.cursor()
        if type_name== 'resource':
            exists = self.get(type_=Resource, hash=item._hash)
            if not exists:
                with item.open() as f:
                    data = Binary(f.read())
                checked_execute(cursor, SQL['add-resource'],
                            {'hash':item._hash,'mediatype':item.media_type,'data':data})
        elif type_name in ['document','binder']:
            args = item.to_dict()
            args['license'] = repr(args['license'])
            args['media_type'] = MEDIATYPES[type_name]
            if 'summary' in args:
                args.pop('summary')
            if 'tree' in args:
                args['content'] = json.dumps(args.pop('tree'))
            if 'cnx-archive-uri' not in args:
                args['cnx-archive-uri'] = None
            # BBB 18-Nov-2014 licensors - deprecated property 'licensors'
            #     needs changed in webview and archive before removing here.
            if 'licensors' in args:
                args['copyright_holders'] = args.pop('licensors')
            # /BBB

            for field in JSON_FIELDS:
                args[field] = psycopg2.extras.Json(args[field])
            checked_execute(cursor, SQL['add-document'], args)

            for user_id, permissions in item.acls.items():
                for permission in set(permissions):
                    checked_execute(cursor, SQL['add-document-acl'], {
                        'uuid': item.id,
                        'user_id': user_id,
                        'permission': permission,
                        })
            for licensor in item.licensor_acceptance:
                # licensor format: {'uid': <str>, 'has_accepted': <bool|None>}
                params = {
                    'uuid': item.id,
                    'user_id': licensor['id'],
                    'has_accepted': licensor['has_accepted'],
                    }
                checked_execute(cursor,
                                SQL['add-document-licensor-acceptance'],
                                params)
        else:
            raise NotImplementedError(type_name)
        return item

    def remove(self, item_or_items):
        """Removes any item or set of items from storage."""
        if isinstance(item_or_items, list):
            raise NotImplementedError()
        item = item_or_items
        type_name= item.__class__.__name__.lower()
        with self.conn.cursor() as cursor:
            if type_name == 'resource':
                checked_execute(cursor, SQL['delete-resource'],
                                {'hash':item._hash})
            elif type_name in ['document', 'binder']:
                params = {'uuid': item.id}
                checked_execute(cursor, SQL['delete-document-acl'], params)
                checked_execute(cursor,
                                SQL['delete-document-licensor-acceptance'],
                                params)
                checked_execute(cursor, SQL['delete-document'],
                                {'id': item.id})
        return item

    def update(self, item_or_items):
        """Updates any item or set of items in storage."""
        if isinstance(item_or_items, list):
            raise NotImplementedError()
        item = item_or_items
        type_name= item.__class__.__name__.lower()
        cursor = self.conn.cursor()
        if type_name == 'resource':
            checked_execute(cursor, SQL['update-resource'],
                        {'hash':item._hash,'mediatype':item.mediatype,'data':Binary(item.data)})
        elif type_name in ['document', 'binder']:
            args = item.to_dict()
            args['license'] = repr(args['license'])
            if 'license_url' in args:
                args.pop('license_url')
            if 'license_text' in args:
                args.pop('license_text')
            if 'media_type' in args:
                args.pop('media_type')
            if 'summary' in args:
                 args.pop('summary')
            if 'cnx-archive-uri' not in args:
                args['cnx-archive-uri'] = None
            if 'tree' in args:
                args['content'] = json.dumps(args.pop('tree'))
            # BBB 18-Nov-2014 licensors - deprecated property 'licensors'
            #     needs changed in webview and archive before removing here.
            if 'licensors' in args:
                args['copyright_holders'] = args.pop('licensors')
            # /BBB

            for field in JSON_FIELDS:
                args[field] = psycopg2.extras.Json(args[field])
            checked_execute(cursor, SQL['update-document'], args)
            checked_execute(cursor, SQL['delete-document-acl'],
                            {'uuid': args['id']})
            for user_id, permissions in item.acls.items():
                for permission in set(permissions):
                    checked_execute(cursor, SQL['add-document-acl'], {
                        'uuid': item.id,
                        'user_id': user_id,
                        'permission': permission,
                        })
            checked_execute(cursor, SQL['delete-document-licensor-acceptance'],
                            {'uuid': args['id']})
            for licensor in item.licensor_acceptance:
                # licensor format: {'uid': <str>, 'has_accepted': <bool|None>}
                params = {
                    'uuid': item.id,
                    'user_id': licensor['id'],
                    'has_accepted': licensor['has_accepted'],
                    }
                checked_execute(cursor,
                                SQL['add-document-licensor-acceptance'],
                                params)
        return item

    def persist(self):
        """Persist/commit the changes."""
        self.conn.commit()

    def abort(self):
        """Abort the changes"""
        self.conn.rollback()

    def search(self, limits, type_=Document, submitter_id=None):
        """Retrieve any ``Document`` objects from storage that matches the
        search terms."""
        if type_ != Document:
            raise NotImplementedError()

        in_progress = ( self.conn.status != STATUS_READY )

        cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        search_terms = []
        for limit_type, term in limits:
            if limit_type != 'text':
                raise NotImplementedError()
            search_terms.append(term.lower())

        title_terms = ['lower(title) ~ %s'] * len(search_terms)
        if submitter_id is None:
            where_clause = '(' + ' OR '.join(title_terms) + ')'
            sqlargs = search_terms
        else:
            where_clause = '(' + ' OR '.join(title_terms) + ") AND submitter->>'id' = %s"
            sqlargs = search_terms + [submitter_id]

        cursor.execute(SQL['search-title'].format(where_clause=where_clause), sqlargs)
        res = cursor.fetchall()
        if not in_progress:
            self.conn.rollback() # Frees the connection
        if res:
            for item in res:
                yield self._reassemble_model_from_document_entry(**item)
        raise StopIteration
