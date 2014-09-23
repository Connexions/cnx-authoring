CREATE TABLE document_acl ( uuid       UUID NOT NULL,
                            user_id    TEXT NOT NULL,
                            permission TEXT NOT NULL,
                            PRIMARY KEY (uuid, user_id, permission),
                            FOREIGN KEY (uuid) REFERENCES document (id) ON DELETE CASCADE
                          );
