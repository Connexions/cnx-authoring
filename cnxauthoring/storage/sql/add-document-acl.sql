-- ###
-- Copyright (c) 2014, Rice University
-- This software is subject to the provisions of the GNU Affero General
-- Public License version 3 (AGPLv3).
-- See LICENCE.txt for details.
-- ###

-- arguments: uuid:uuid; user_id:string, permission:string

INSERT INTO document_acl (uuid, user_id, permission)
    VALUES (%(uuid)s, %(user_id)s, %(permission)s);
