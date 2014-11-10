-- ###
-- Copyright (c) 2014, Rice University
-- This software is subject to the provisions of the GNU Affero General
-- Public License version 3 (AGPLv3).
-- See LICENCE.txt for details.
-- ###

-- arguments: uuid:uuid; user_id:string, has_accepted:bool

INSERT INTO document_licensor_acceptance (uuid, user_id, has_accepted)
    VALUES (%(uuid)s, %(user_id)s, %(has_accepted)s);
