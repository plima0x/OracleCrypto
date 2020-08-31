create or replace PACKAGE BODY PKG_CRYPTO IS


  PROCEDURE ENCRYPT(p_id_user  IN users.id%TYPE)
  IS
     encrypted_input     VARCHAR2(200);
     encrypted_password  RAW(2000);
     num_key_bytes       NUMBER := 256 / 8;
     key_bytes_raw       RAW(32);
     encryption_type     PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES256
                                      + DBMS_CRYPTO.CHAIN_CBC
                                      + DBMS_CRYPTO.PAD_PKCS5;

     iv_raw              RAW(16);
     l_password          users.password%TYPE;
     l_already_crypto    VARCHAR2(1);
     no_user_data     EXCEPTION;
  BEGIN
    -- Verifying if the there is an user registered in the users_pass table. If so, the user password has been encrypted already.
    BEGIN
      SELECT 'S'
      INTO  l_already_crypto
      FROM users_pass
      WHERE id_user = p_id_user;

    EXCEPTION
      WHEN NO_DATA_FOUND THEN
         l_already_crypto := 'N';
      WHEN OTHERS THEN
         RAISE_APPLICATION_ERROR(-20001, 'Error while verifying if the users password is encrypted. User id: '|| p_id_user ||'. Error details: '|| SQLERRM);
    END;

    IF l_already_crypto ='S' THEN

      RAISE_APPLICATION_ERROR(-20001, 'User password has been encrypted already!'||'. User id: '|| p_id_user);

    ELSE
     -- Searching for the user password in the users table.
      BEGIN
        SELECT password
        INTO l_password
        FROM users
        WHERE id = p_id_user;

      EXCEPTION
        WHEN NO_DATA_FOUND THEN
          RAISE_APPLICATION_ERROR(-20001, 'Error in the encrypt procedure. User that has the id '|| p_id_user || ' not found.');
        WHEN OTHERS THEN
          RAISE_APPLICATION_ERROR(-20001, 'Error while searching for the user that has the id '|| p_id_user);
      END;

      key_bytes_raw := DBMS_CRYPTO.RANDOMBYTES(num_key_bytes);
      iv_raw        := DBMS_CRYPTO.RANDOMBYTES(16);
      encrypted_password := DBMS_CRYPTO.ENCRYPT(
          src => UTL_I18N.STRING_TO_RAW(l_password, 'AL32UTF8'),
          typ => encryption_type,
          key => key_bytes_raw,
          iv =>  iv_raw
      );
     -- Inserting informations for decrypting the user password in the users_pass table.
      BEGIN
        INSERT INTO users_pass
        (id_user,
          key,
          iv_raw)
        VALUES
        (p_id_user,
        key_bytes_raw,
        iv_raw

        );
      EXCEPTION
         WHEN OTHERS THEN
           RAISE_APPLICATION_ERROR(-20001,'Error while inserting crypted password' || '. User id: '|| p_id_user ||'. Error details: ' || SQLERRM);
       END;

       BEGIN
        -- Updating the users normal password to a encrypted password.
        UPDATE users
        SET password = UTL_I18N.RAW_TO_CHAR(encrypted_password, 'AL32UTF8')
        WHERE id = p_id_user;
      EXCEPTION
        WHEN OTHERS THEN
          RAISE_APPLICATION_ERROR(-20001,'Error while updating users table'||'. User id: '|| p_id_user ||'. Error details: '|| SQLERRM);

      END;

      COMMIT;

   END IF;

  END ENCRYPT;

  PROCEDURE DECRYPT(p_id_user IN users.id%TYPE)
  IS
  encrypted_password users.password%TYPE;
  key                users_pass.key%TYPE;
  iv_raw             users_pass.iv_raw%TYPE;
  decrypted_password VARCHAR2(200);
  encryption_type  PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES256
                                  + DBMS_CRYPTO.CHAIN_CBC
                                  + DBMS_CRYPTO.PAD_PKCS5;
  BEGIN
    BEGIN
      SELECT  u.password, c.key, c.iv_raw
      INTO   encrypted_password, key, iv_raw
      FROM users u, users_pass c
      WHERE u.id = c.id_user
      AND u.id = p_id_user;

    EXCEPTION
      WHEN NO_DATA_FOUND THEN
        RAISE_APPLICATION_ERROR(-20001, 'Error in the decrypt procedure. User that has the id '|| p_id_user || ' not found.');
      WHEN OTHERS THEN
        RAISE_APPLICATION_ERROR(-20001, 'Error while searching data for decryption of the password'|| '. User id: '|| p_id_user ||'. Error details: '|| SQLERRM);
    END;

    decrypted_password := DBMS_CRYPTO.DECRYPT
    (
      src => UTL_I18N.STRING_TO_RAW(encrypted_password, 'AL32UTF8'),
      typ => encryption_type,
      key => key,
      iv  => iv_raw
    );

    BEGIN
      UPDATE users
      SET password =  UTL_I18N.RAW_TO_CHAR(decrypted_password, 'AL32UTF8')
      WHERE id = p_id_user;

    EXCEPTION
      WHEN OTHERS THEN
        RAISE_APPLICATION_ERROR(-20001, 'Error while setting the decrypted password'|| '. User id: '|| p_id_user ||'. Error details: '|| SQLERRM);

    END;

    BEGIN
      DELETE FROM users_pass
      WHERE id_user = p_id_user;
    EXCEPTION
      WHEN OTHERS THEN
        RAISE_APPLICATION_ERROR(-20001, 'Error while deleting the old register in the users_pass table'|| '. User id: '|| p_id_user ||'. Error details: '|| SQLERRM);
    END;

    COMMIT;

  END DECRYPT;

END PKG_CRYPTO;
