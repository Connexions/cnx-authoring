CREATE TABLE document ( id              uuid primary key, 
                        title           text not null,
                        created         timestamptz not null,
                        modified        timestamptz not null,
                        license         text not null,
                        language        text not null,
                        derived_from    text,
                        content         text,
                        abstract        text,
                        submitter       text not null
                    );
