CREATE OR REPLACE PACKAGE pkg_crypto IS

  PROCEDURE encrypt(p_id_user  IN users.id%TYPE);

PROCEDURE decrypt(p_id_user IN users.id%TYPE);


END pkg_crypto;
