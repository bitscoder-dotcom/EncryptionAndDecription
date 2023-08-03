package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;

public class TripleDesExample {
    public static String encrypt(String toEncrypt, boolean useHashing) throws Exception {
        byte[] keyArray;
        byte[] toEncryptArray = toEncrypt.getBytes("UTF-8");

        // Get the key from config file
        String key = "SecurityKey"; // Replace with the actual key from your config file

        // If hashing use get hashcode regards to your key
        if (useHashing) {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            keyArray = md5.digest(key.getBytes("UTF-8"));
        } else {
            keyArray = key.getBytes("UTF-8");
        }

        SecretKey secretKey = new SecretKeySpec(keyArray, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] resultArray = cipher.doFinal(toEncryptArray);

        // Return the encrypted data into unreadable string format
        return Base64.getEncoder().encodeToString(resultArray);
    }

    public static String decrypt(String cipherString, boolean useHashing) throws Exception {
        byte[] keyArray;

        // Get the byte code of the string
        byte[] toEncryptArray = Base64.getDecoder().decode(cipherString);

        // Get your key from config file to open the lock!
        String key = "SecurityKey"; // Replace with the actual key from your config file

        if (useHashing) {
            // If hashing was used get the hash code with regards to your key
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            keyArray = md5.digest(key.getBytes("UTF-8"));
        } else {
            // If hashing was not implemented get the byte code of the key
            keyArray = key.getBytes("UTF-8");
        }

        SecretKey secretKey = new SecretKeySpec(keyArray, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] resultArray = cipher.doFinal(toEncryptArray);

        // Return the decrypted TEXT
        return new String(resultArray, "UTF-8");
    }
}

