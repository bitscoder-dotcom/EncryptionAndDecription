package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class TripleDesExample {
    private static final String TDES_ECB_NONE = "DESede/ECB/NoPadding";

    public static void main(String[] args) throws Exception {

        String passwordStr = "TM@1234$";
        byte[] passwordKeyRaw = generate24ByteKey(passwordStr);

        byte[] passwordRaw = passwordStr.getBytes(StandardCharsets.UTF_8);
        byte[] passwordHash = dbmsCryptoEncrypt(passwordRaw, TDES_ECB_NONE, passwordKeyRaw);
        System.out.println("Encrypted password hash: "+ Arrays.toString(passwordHash));

        String nextChallengeStr = "47507110";
        byte[] nextChallengeRaw = nextChallengeStr.getBytes(StandardCharsets.UTF_8);
        byte[] cryptPassword = dbmsObfuscationToolKitDESencypt(nextChallengeRaw, passwordKeyRaw, TDES_ECB_NONE);
        System.out.println("Decrypted challenge: "+new String(cryptPassword, StandardCharsets.UTF_8));
    }

    private static byte[] dbmsCryptoEncrypt(byte[] src, String typ, byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, "DESede");
        Cipher cipher = Cipher.getInstance(typ);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(src);
    }

    public static byte[] dbmsObfuscationToolKitDESencypt(byte[] input, byte[] key, String typ) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, "DESede");
        Cipher cipher = Cipher.getInstance(typ);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(input);
    }

    private static byte[] generate24ByteKey(String password) throws Exception{
        int keyLength = 24;
        int iterations = 10_000;
        byte[] salt = generateRandomSalt();

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength*8);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey tmp = factory.generateSecret(spec);
        return tmp.getEncoded();
    }

    private static byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private static String padRight(String str, int length) {
        return String.format("%1$-"+length+"s", str);
    }
}
