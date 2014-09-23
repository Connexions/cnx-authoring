-- ###
-- Copyright (c) 2014, Rice University
-- This software is subject to the provisions of the GNU Affero General
-- Public License version 3 (AGPLv3).
-- See LICENCE.txt for details.
-- ###

SELECT *
FROM document d JOIN document_acl da ON d.id = da.uuid
WHERE {where_clause}
  AND da.user_id = %(user_id)s
  AND da.permission IN %(permissions)s
ORDER BY d.revised DESC;
