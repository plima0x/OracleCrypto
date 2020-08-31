CREATE TABLE users
( id       NUMBER(6)      NOT NULL,
  name     VARCHAR2(50)   NOT NULL,
  password VARCHAR2(2000)  NOT NULL
);

ALTER TABLE users
ADD CONSTRAINT pk_id_user
PRIMARY KEY(id);


CREATE TABLE users_pass
( id_user    NUMBER(6) NOT NULL,
  key        RAW(32)   NOT NULL,
  iv_raw     RAW(16)   NOT NULL
);

ALTER TABLE users_pass
ADD CONSTRAINT pk_id_user_pass
PRIMARY KEY(id_user);

ALTER TABLE users_pass
ADD CONSTRAINT fk_id_user_pass
FOREIGN KEY(id_user)
REFERENCES users(id) ON DELETE CASCADE;
