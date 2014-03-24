-- ###
-- Copyright (c) 2014, Rice University
-- This software is subject to the provisions of the GNU Affero General
-- Public License version 3 (AGPLv3).
-- See LICENCE.txt for details.
-- ###

-- arguments: hash:string; mediatype:string, data:bytea

INSERT INTO resource (hash,mediatype,data) VALUES( %(hash)s, %(mediatype)s, %(data)s);
