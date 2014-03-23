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
            title = %(title)s, modified = %(modified)s, 
            content = %(content)s, derived_from = %(derived_from)s,
            submitter = %(submitter)s
WHERE id  = %(id)s
