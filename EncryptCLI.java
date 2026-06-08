package com.example.networkrestricted;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.Map;
import javax.crypto.SecretKey;

public class EncryptCLI {
    public static void main(String[] args) {
        try {
            // Ensure RSA keys exist
            if (!Files.exists(Paths.get("recipient_public.der")) || !Files.exists(Paths.get("recipient_private.der"))) {
                System.out.println("Generating RSA key pair...");
                RSAUtil.generateAndSaveKeyPair("recipient_public.der", "recipient_private.der");
                System.out.println("RSA keys generated.");
            }

            String plainText = null;
            String outputFile = "encrypted_payload.json";
            // simple arg parsing
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                if ("-m".equals(a) || "--message".equals(a)) {
                    if (i + 1 < args.length) {
                        plainText = args[i + 1];
                        i++;
                    }
                } else if ("-o".equals(a) || "--output".equals(a)) {
                    if (i + 1 < args.length) {
                        outputFile = args[i + 1];
                        i++;
                    }
                } else if ("-h".equals(a) || "--help".equals(a)) {
                    System.out.println("Usage: java -cp <cp> com.example.networkrestricted.EncryptCLI [-m \"message\"] [-o output.json]");
                    return;
                }
            }

            // Interactive fallback
            if (plainText == null || plainText.trim().isEmpty()) {
                java.io.Console console = System.console();
                if (console != null) {
                    String input = console.readLine("Enter the message to encrypt (leave empty to use default): ");
                    if (input != null && !input.trim().isEmpty()) {
                        plainText = input;
                    }
                } else {
                    System.out.print("Enter message (or blank for default) and press Enter: ");
                    java.util.Scanner sc = new java.util.Scanner(System.in);
                    if (sc.hasNextLine()) {
                        String in = sc.nextLine();
                        if (in != null && !in.trim().isEmpty()) plainText = in;
                    }
                }
            }

            if (plainText == null || plainText.trim().isEmpty()) {
                plainText = System.getenv("MESSAGE");
            }
            if (plainText == null || plainText.trim().isEmpty()) {
                plainText = "This is a network-restricted message.";
            }

            // Generate AES and encrypt
            SecretKey aesKey = AESUtil.generateAESKey();
            String cipherText = AESUtil.encrypt(plainText, aesKey);

            // Encrypt AES key with recipient public key
            PublicKey recipientPub = RSAUtil.loadPublicKey("recipient_public.der");
            String encryptedAESKey = RSAUtil.encryptAESKey(aesKey.getEncoded(), recipientPub);

            // Capture wifi fingerprint
            Map<String,Integer> wifiFP = null;
            try {
                wifiFP = WifiScanner.getWifiFingerprint();
                WifiScanner.saveFingerprint(wifiFP, "wifi_fingerprint.json");
            } catch (Exception e) {
                System.out.println("Warning: failed to capture Wi-Fi fingerprint: " + e.getMessage());
            }

            // Create payload
            String payload = PayloadUtil.createPayload(cipherText, encryptedAESKey, wifiFP);
            Files.write(Paths.get(outputFile), payload.getBytes("UTF-8"));
            System.out.println("Payload written to: " + outputFile);

        } catch (Exception e) {
            System.err.println("Encryption failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
