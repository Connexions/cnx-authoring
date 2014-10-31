# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import json
import unittest
import uuid

from pyramid import testing
from pyramid.renderers import JSON


class ModelJSONRendering(unittest.TestCase):
    """Ensure the models render to JSON.
    Note that the adaptation to JSON is transparent
    through view configuration of a 'renderer'.
    """

    def setUp(self):
        self.config = testing.setUp()

    tearDown = testing.tearDown

    def render(self, things, adapters=()):
        """Manually call the renderer and pass in the adapters.
        Adapters get passed in because the component registry is scoped
        to the test case.
        """
        renderer = JSON(adapters=adapters)
        return renderer(things)(things, {})

    def test_document_to_json(self):
        id = uuid.uuid4()
        title = "Too late"
        from ..models import Document
        document = Document(title, id=id)

        self.maxDiff = None
        expected_json = {
            'id': str(id),
            'title': title,
            'created': document.metadata['created'].isoformat(),
            'revised': document.metadata['revised'].isoformat(),
            'mediaType': Document.mediatype,
            'language': 'en',
            'version': 'draft',
            'submitter': None,
            'authors': [],
            'publishers': [],
            'licensors': [],
            'editors': [],
            'translators': [],
            'illustrators': [],
            'derivedFrom': None,
            'derivedFromTitle': None,
            'derivedFromUri': None,
            'abstract': u'',
            'content': u'',
            'containedIn': [],
            'license': {
                'url': 'http://creativecommons.org/licenses/by/4.0/',
                'abbr': 'by',
                'name': 'Attribution',
                'version': '4.0',
                },
            'subjects': [],
            'keywords': [],
            'state': 'Draft',
            'publication': None,
            }
        expected_json = json.dumps(expected_json)

        # Call the renderer
        from ..modifiers import JSON_RENDERERS
        json_document = self.render(document, adapters=JSON_RENDERERS)

        self.assertEqual(json.loads(json_document), json.loads(expected_json))
