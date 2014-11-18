CREATE TABLE document_licensor_acceptance (
    uuid               uuid,
    user_id            text,
    has_accepted       boolean,
    primary key ("uuid", "user_id"),
    foreign key ("uuid") references document ("id")
    );
