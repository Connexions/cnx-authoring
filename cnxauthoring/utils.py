# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import datetime
import io
import re

import cnxepub.models
from cnxquerygrammar.query_parser import grammar, DictFormater
from parsimonious.exceptions import IncompleteParseError


def utf8(item):
    if isinstance(item, list):
        return [utf8(i) for i in item]
    if isinstance(item, dict):
        return {utf8(k): utf8(v) for k, v in item.items()}
    try:
        return item.decode('utf-8')
    except:
        return item

def change_dict_keys(data, func):
    for k in data.keys():
        _k = func(k)
        if _k != k:
            data[_k] = data.pop(k)
        if isinstance(data[_k], dict):
            change_dict_keys(data[_k], func)

def camelcase_to_underscore(camelcase):
    def replace(match):
        char = match.group(1)
        return '_{}'.format(char.lower())
    return re.sub('([A-Z])', replace, camelcase)

def underscore_to_camelcase(underscore):
    def replace(match):
        char = match.group(1)
        return '{}'.format(char.upper())
    return re.sub('_([a-z])', replace, underscore)

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

def filter_binder_documents(binder, documents):
    """walks through a binder, converting any draft documents that are
        not in the list of documents into documentpointers."""
    docids = [d.id for d in documents]
    for i, model in enumerate(binder):
        if isinstance(model, cnxepub.models.TranslucentBinder): # section/subcollection
            filter_binder_documents(model, documents)

        elif isinstance(model,cnxepub.models.Document):
            if model.id not in docids:
                binder.pop(i) # remove it
                # Is it new?
                if model.get_uri('cnx-archive'):
                    #convert to documentpointer
                    dp = epub.models.DocumentPointer(model.get_uri('cnx-archive'))
                    binder.insert(i,dp)

def build_epub(contents, submitter, submitlog):
    from .models import DEFAULT_LICENSE, Binder

    epub = io.BytesIO()
    documents = []
    binders = []
    for i,content in enumerate(contents,1):
        if type(content) == list: # book + pages in a list
            if isinstance(content[0], Binder): 
                content[0].publish_prep()
                filter_binder_documents(content[0], content[1:])
                binders.append(content[0])
            else:  # belt and suspenders - seems to be an extra level of lists - filter out docs
                for doc in content:
                    if isinstance(doc,cnxepub.models.Document):
                        doc.publish_prep()
                        documents.append(doc)
        elif isinstance(content, Binder): # Special case: toplevel is book + pages
            content.publish_prep()
            filter_binder_documents(content, contents[i:])
            binders.append(content)
            break # eat the whole list
        elif isinstance(content,cnxepub.models.Document):
            content.publish_prep()
            documents.append(content)
        

    if documents:
        license_text = ' '.join([DEFAULT_LICENSE.name, DEFAULT_LICENSE.abbr,
            DEFAULT_LICENSE.version])
        binders.append(cnxepub.models.TranslucentBinder(
                metadata={
                    'title': 'Publications binder',
                    'created': datetime.datetime.now(),
                    'revised': datetime.datetime.now(),
                    'license_text': license_text,
                    'license_url': DEFAULT_LICENSE.url,
                    },
                nodes=documents))
    cnxepub.adapters.make_publication_epub(
            binders, submitter, submitlog, epub)
    epub.seek(0)
    return epub
