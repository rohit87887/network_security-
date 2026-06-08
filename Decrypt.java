package com.example.networkrestricted;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import org.json.JSONObject;

public class Decrypt {
    public static void main(String[] args) {
        try {
            // 1) Read the encrypted payload (optional filename argument)
            String payloadFile = "encrypted_payload.json";
            if (args != null && args.length > 0 && args[0] != null && !args[0].trim().isEmpty()) {
                payloadFile = args[0];
            }
            String payloadStr = new String(Files.readAllBytes(Paths.get(payloadFile)), "UTF-8");
            JSONObject payload = new JSONObject(payloadStr);
            
            // 2) Get encrypted AES key and ciphertext
            String encryptedAESKeyStr = payload.getString("encryptedAESKey");
            String cipherText = payload.getString("cipherText");
            
            // 3) Load private key and decrypt AES key
            PrivateKey privateKey = RSAUtil.loadPrivateKey("recipient_private.der");
            byte[] decryptedAESKeyBytes = RSAUtil.decryptAESKey(encryptedAESKeyStr, privateKey);
            SecretKey aesKey = AESUtil.fromBytes(decryptedAESKeyBytes);
            
            // 4) Show detailed encryption information
            System.out.println("\n=== Decryption Process Details ===");
            
            System.out.println("Step 1: Encrypted Payload Information");
            System.out.println("Payload File: " + payloadFile);
            System.out.println("Payload Size: " + payloadStr.length() + " bytes");
            
            System.out.println("\nStep 2: RSA Key Details");
            System.out.println("Private Key Algorithm: " + privateKey.getAlgorithm());
            System.out.println("Private Key Format: " + privateKey.getFormat());
            System.out.println("Key Size: " + ((java.security.interfaces.RSAPrivateKey)privateKey).getModulus().bitLength() + " bits");
            
            System.out.println("\nStep 3: AES Key Recovery");
            String aesKeyBase64 = java.util.Base64.getEncoder().encodeToString(aesKey.getEncoded());
            System.out.println("Encrypted AES Key Length: " + encryptedAESKeyStr.length() + " characters");
            System.out.println("Decrypted AES Key (Base64): " + aesKeyBase64);
            System.out.println("AES Key Algorithm: " + aesKey.getAlgorithm());
            System.out.println("AES Key Length: " + (aesKey.getEncoded().length * 8) + " bits");
            
            System.out.println("\nStep 4: Encrypted Content");
            String[] parts = cipherText.split(":");
            System.out.println("IV (Base64): " + parts[0]);
            System.out.println("Encrypted Text (Base64): " + parts[1]);
            
            // 5) Decrypt and show the message with details
            String decryptedMessage = AESUtil.decrypt(cipherText, aesKey);
            System.out.println("\nStep 5: Decryption Result");
            System.out.println("Decrypted Message: " + decryptedMessage);
            System.out.println("Message Length: " + decryptedMessage.length() + " characters");
            System.out.println("Message Size: " + decryptedMessage.getBytes("UTF-8").length + " bytes");
            System.out.println("-------------------------------");
            
        } catch (Exception e) {
            System.err.println("Decryption failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}