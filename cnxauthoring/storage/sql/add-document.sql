-- ###
-- Copyright (c) 2014, Rice University
-- This software is subject to the provisions of the GNU Affero General
-- Public License version 3 (AGPLv3).
-- See LICENCE.txt for details.
-- ###

-- arguments: hash:string; mediatype:string, data:bytea

INSERT INTO document (license, language, created, abstract, media_type,
                      title, revised, content, derived_from, submitter,
                      authors, id, derived_from_title, derived_from_uri,
                      cnx_archive_uri, subjects, keywords, state,
                      publication, publishers, contained_in, licensors,
                      editors, translators, illustrators)
    VALUES(%(license)s, %(language)s, %(created)s, %(abstract)s, %(media_type)s,
           %(title)s, %(revised)s, %(content)s, %(derived_from)s, %(submitter)s,
           %(authors)s, %(id)s, %(derived_from_title)s, %(derived_from_uri)s,
           %(cnx-archive-uri)s, %(subjects)s, %(keywords)s, %(state)s,
           %(publication)s, %(publishers)s, %(contained_in)s, %(licensors)s,
           %(editors)s, %(translators)s, %(illustrators)s);
