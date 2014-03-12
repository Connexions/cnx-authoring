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
            'submitter': 'username',
            }
        from ..schemata import document_schema
        appstruct = document_schema.bind().deserialize(cstruct)
        self.assertTrue(isinstance(appstruct['created'], datetime.datetime))
        self.assertTrue(isinstance(appstruct['created'], datetime.datetime))


    @unittest.skip("not implemented")
    def test_datetime_fields_in_future(self):
        pass

    @unittest.skip("not implemented")
    def test_license_as_url(self):
        # Given the {..., 'license': '<license-url-value>', ...}
        #   prepare it to a LicenseSchema based value.
        pass

    @unittest.skip("not implemented")
    def test_id_dropped_w_new(self):
        # If the schema is bound with ``bind(new=True)``,
        #   then drop the id value if one is given,
        #   this prevents a user from specifying an id,
        #   but allows the id to pass through on update.
        pass
