-- ###
-- Copyright (c) 2014, Rice University
-- This software is subject to the provisions of the GNU Affero General
-- Public License version 3 (AGPLv3).
-- See LICENCE.txt for details.
-- ###

SELECT  id, title, created, revised, license, language, media_type, derived_from,
derived_from_uri, derived_from_title, content, abstract, submitter, authors,
publishers, copyright_holders, editors, translators, illustrators, subjects,
keywords, state, publication, cnx_archive_uri, version, contained_in, print_style
from document WHERE {where_clause} 
