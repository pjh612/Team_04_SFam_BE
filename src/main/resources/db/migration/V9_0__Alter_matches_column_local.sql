ALTER TABLE sfam.users
    ADD COLUMN local_name varchar(30);
ALTER TABLE matches
    ADD column local_name varchar(30);
