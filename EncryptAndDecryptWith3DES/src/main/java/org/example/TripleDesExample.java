package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TripleDesExample {
    private static final String TDES_ECB_NONE = "DESede/ECB/NoPadding";

    public static void main(String[] args) throws Exception {
        String passwordStr = "TM@1234$";
        String passwordKeyStr = padRight(passwordStr, 24);
        byte[] passwordRaw = passwordStr.getBytes(StandardCharsets.UTF_8);
        byte[] passwordKeyRaw = passwordKeyStr.getBytes(StandardCharsets.UTF_8);
        byte[] passwordHash = dbmsCryptoEncrypt(passwordRaw, TDES_ECB_NONE, passwordKeyRaw);
        System.out.println("Encrypted password hash: " + Arrays.toString(passwordHash));

//        String nextChallengeStr = "47507110";
//        byte[] nextChallengeRaw = nextChallengeStr.getBytes(StandardCharsets.UTF_8);
//        byte[] cryptPassword = dbmsObfuscationToolkitDESencrypt(nextChallengeRaw, passwordKeyRaw, TDES_ECB_NONE);
        byte[] decryptedPassword = dbmsObfuscationToolkitDESencrypt(passwordHash, passwordKeyRaw, TDES_ECB_NONE);
//        System.out.println("Decrypted challenge: " + new String(cryptPassword, StandardCharsets.UTF_8));
        System.out.println("Decrypted password: " + new String(decryptedPassword, StandardCharsets.UTF_8));
    }

    private static String padRight(String str, int length) {
        return String.format("%1$-" + length + "s", str);
    }

    private static byte[] dbmsCryptoEncrypt(byte[] src, String typ, byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, "DESede");
        Cipher cipher = Cipher.getInstance(typ);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(src);
    }

    public static byte[] dbmsObfuscationToolkitDESencrypt(byte[] input, byte[] key, String typ) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, "DESede");
        Cipher cipher = Cipher.getInstance(typ);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(input);
    }
}

