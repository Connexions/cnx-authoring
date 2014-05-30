# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import datetime
import unittest


class DocumentSchemaTestCase(unittest.TestCase):

    def test_datetime_fields_missing(self):
        cstruct = {
            'title': 'required title',
            'submitter': {
                'id': 'username',
                },
            'authors': [{
                'id': 'username',
                }],
            'publishers': [{
                'id': 'username',
                }],
            }
        from ..schemata import document_schema
        appstruct = document_schema.bind().deserialize(cstruct)
        self.assertTrue(isinstance(appstruct['created'], datetime.datetime))
        self.assertTrue(isinstance(appstruct['created'], datetime.datetime))


class UserSchemaTestCase(unittest.TestCase):

    def test_missing_optional_fields(self):
        cstruct = {
            'id': 'me',
            }
        from ..schemata import UserSchema
        user_schema = UserSchema()
        appstruct = user_schema.bind().deserialize(cstruct)
        self.assertEqual(appstruct, {
            'id': 'me',
            'email': '',
            'firstname': '',
            'surname': '',
            'type': 'cnx-id',
            })
