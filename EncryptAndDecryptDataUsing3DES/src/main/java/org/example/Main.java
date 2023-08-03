package org.example;

import static org.example.TripleDesExample.decrypt;
import static org.example.TripleDesExample.encrypt;

public class Main {
    public static void main(String[] args) throws Exception {
        String originalText = "This is a test message";
        String encryptedText = encrypt(originalText, true);
        String decryptedText = decrypt(encryptedText, true);

        System.out.println("Original text: " + originalText);
        System.out.println("Encrypted text: " + encryptedText);
        System.out.println("Decrypted text: " + decryptedText);
    }

}