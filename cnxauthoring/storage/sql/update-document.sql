-- ###
-- Copyright (c) 2014, Rice University
-- This software is subject to the provisions of the GNU Affero General
-- Public License version 3 (AGPLv3).
-- See LICENCE.txt for details.
-- ###

-- arguments: hash:string; mediatype:string, data:bytea

UPDATE document 
        SET license = %(license)s, language = %(language)s, 
            created = %(created)s, abstract = %(abstract)s,
            title = %(title)s, revised = %(revised)s, 
            content = %(content)s, derived_from = %(derived_from)s,
            derived_from_title = %(derived_from_title)s,
            derived_from_uri = %(derived_from_uri)s,
            submitter = %(submitter)s, subjects = %(subjects)s,
            keywords = %(keywords)s, state = %(state)s,
            publication = %(publication)s
WHERE id  = %(id)s
