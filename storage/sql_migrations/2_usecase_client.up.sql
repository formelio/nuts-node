-- usecase_client_list contains the configured use cases and tracks the timestamp to update deltas.
create table usecase_client_list
(
    usecase_id text    not null primary key,
    timestamp  integer not null
);

-- usecase_client_entries is an entry on a list (usecase_client_list)
create table usecase_client_entries
(
    id                      text    not null primary key,
    usecase_id              text    not null,
    presentation_id         text    not null,
    presentation_raw        text    not null,
    presentation_expiration integer not null,
    CONSTRAINT fk_uc_client_list_id FOREIGN KEY (id) REFERENCES usecase_client_list (usecase_id) ON DELETE CASCADE
);

-- usecase_client_credential is a credential in a list entry (usecase_client_entry)
-- We could do without the table, but having it allows to have a normalized index for credential properties that appear on every credential.
-- Then we don't need rows in the properties table for them (having a column for those is faster than having a row in the properties table which needs to be joined).
create table usecase_client_credential
(
    id                    text not null primary key,
    entry_id              text not null,
    credential_id         text not null,
    credential_issuer     text not null,
    credential_subject_id text not null,
    -- for now, credentials with at most 2 types are supported.
    -- The type stored in the type column will be the 'other' type, not being 'VerifiableCredential'.
    -- When credentials with 3 or more types appear, we could have to use a separate table for the types.
    credential_type       text,
    CONSTRAINT fk_uc_client_list_entry_id FOREIGN KEY (entry_id) REFERENCES usecase_client_entries (id) ON DELETE CASCADE
);

create table usecase_client_credential_props
(
    id    text not null,
    key   text not null,
    value text,
    PRIMARY KEY (id, key),
    -- cascading delete: if the presentation gets deleted, the properties get deleted as well
    CONSTRAINT fk_uc_client_vc_id FOREIGN KEY (id) REFERENCES usecase_client_credential (id) ON DELETE CASCADE
);