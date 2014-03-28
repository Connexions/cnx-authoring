CREATE TABLE document ( id              uuid primary key, 
                        title           text not null,
                        created         timestamptz not null,
                        revised         timestamptz not null,
                        license         text not null,
                        language        text not null,
                        media_type      text not null,
                        derived_from    text,
                        content         text,
                        abstract        text,
                        submitter       text not null,
                        subjects        text[],
                        keywords        text[]
                    );
