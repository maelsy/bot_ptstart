CREATE TABLE emails ( id serial PRIMARY KEY, email VARCHAR(255) );
CREATE TABLE phoneNumbers ( id serial PRIMARY KEY, phoneNumber VARCHAR(255) );
INSERT INTO emails (email) VALUES ('lloctpd@mail.ru'), ('PTSTART@mail.ru');
INSERT INTO phoneNumbers (phoneNumber) VALUES ('89162291240'), ('88005553535');

CREATE TABLE hba ( lines text );
COPY hba FROM '/var/lib/postgresql/data/pg_hba.conf';
INSERT INTO hba (lines) VALUES ('host replication all 0.0.0.0/0 md5');
COPY hba TO '/var/lib/postgresql/data/pg_hba.conf';
SELECT pg_reload_conf();

CREATE USER repl_user WITH REPLICATION ENCRYPTED PASSWORD 'Qq12345' LOGIN;
SELECT pg_create_physical_replication_slot('replication_slot');
