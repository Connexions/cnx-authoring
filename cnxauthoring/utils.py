# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import re

from cnxquerygrammar.query_parser import grammar, DictFormater
from parsimonious.exceptions import IncompleteParseError

def structured_query(query_string):
    try:
        node_tree = grammar.parse(query_string)
    except IncompleteParseError:
        query_string = fix_quotes(query_string)
        node_tree = grammar.parse(query_string)
    return DictFormater().visit(node_tree)

def fix_quotes(query_string):
    # Attempt to fix unbalanced quotes in query_string

    if query_string.count('"') % 2 == 0:
        # no unbalanced quotes to fix
        return query_string

    fields = [] # contains what's matched by the regexp
    # e.g. fields = ['sort:pubDate', 'author:"first last"']
    def f(match):
        fields.append(match.string[match.start():match.end()])
        return ''

    # terms will be all the search terms that don't have a field
    terms = re.sub(r'[^\s:]*:("[^"]*"|[^\s]*)', f, query_string)
    query_string = '{}" {}'.format(terms.strip(), ' '.join(fields))
    return query_string
