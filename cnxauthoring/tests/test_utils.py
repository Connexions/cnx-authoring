# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###

import unittest

from .. import utils

class UtilsTests(unittest.TestCase):
    def test_change_dict_keys(self):
        data = {
                'id': '1234',
                'deriveFrom': 'uuid@version',
                'nextLevel': {
                    'anotherLevel': {
                        'someOtherThing': 'value',
                        },
                    },
                }
        utils.change_dict_keys(data, utils.camelcase_to_underscore)
        self.assertEqual(data, {
            'id': '1234',
            'derive_from': 'uuid@version',
            'next_level': {
                'another_level': {
                    'some_other_thing': 'value',
                    },
                },
            })

    def test_camelcase_to_underscore(self):
        c2u = utils.camelcase_to_underscore

        self.assertEqual(c2u('id'), 'id')
        self.assertEqual(c2u('deriveFrom'), 'derive_from')
        self.assertEqual(c2u('someOtherThing'), 'some_other_thing')

    def test_underscore_to_camelcase(self):
        u2c = utils.underscore_to_camelcase

        self.assertEqual(u2c('id'), 'id')
        self.assertEqual(u2c('derive_from'), 'deriveFrom')
        self.assertEqual(u2c('some_other_thing'), 'someOtherThing')
