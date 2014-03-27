-- ###
-- Copyright (c) 2014, Rice University
-- This software is subject to the provisions of the GNU Affero General
-- Public License version 3 (AGPLv3).
-- See LICENCE.txt for details.
-- ###

-- arguments: hash:string; mediatype:string, data:bytea

INSERT INTO document (license, language, created, abstract, media_type,
                      title, revised, content, derived_from, submitter, id) 
        VALUES(%(license)s, %(language)s, %(created)s, %(abstract)s, %(media_type)s,
               %(title)s, %(revised)s, %(content)s, %(derived_from)s, %(submitter)s, %(id)s);
