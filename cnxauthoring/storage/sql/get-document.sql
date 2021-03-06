-- ###
-- Copyright (c) 2014, Rice University
-- This software is subject to the provisions of the GNU Affero General
-- Public License version 3 (AGPLv3).
-- See LICENCE.txt for details.
-- ###

WITH docids as (SELECT distinct id
FROM document d JOIN document_acl da ON d.id = da.uuid
WHERE {where_clause}
  AND da.user_id = %(user_id)s
  AND da.permission IN %(permissions)s
) 
select * from document join docids on document.id = docids.id
ORDER BY revised DESC;
