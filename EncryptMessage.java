package com.example.networkrestricted;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.crypto.SecretKey;

public class EncryptMessage {
    // Helper: format DER bytes into PEM with 64-char lines
    private static String toPem(byte[] derBytes, String beginHeader, String endHeader) {
        String b64 = java.util.Base64.getEncoder().encodeToString(derBytes);
        StringBuilder sb = new StringBuilder();
        sb.append(beginHeader).append('\n');
        int idx = 0;
        while (idx < b64.length()) {
            int end = Math.min(idx + 64, b64.length());
            sb.append(b64, idx, end).append('\n');
            idx = end;
        }
        sb.append(endHeader);
        return sb.toString();
    }
    public static void main(String[] args) {
        try {
            // Default options
            String messageArg = null;
            String outputFile = "encrypted_payload.json";
            boolean showKeys = false;
            boolean showPrivate = false;
            boolean useKdf = false;

            // Simple arg parsing
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                switch (a) {
                    case "-m":
                    case "--message":
                        if (i + 1 < args.length) { messageArg = args[++i]; }
                        break;
                    case "-o":
                    case "--output":
                        if (i + 1 < args.length) { outputFile = args[++i]; }
                        break;
                    case "--show-keys":
                        showKeys = true; break;
                    case "--show-private":
                        showPrivate = true; break;
                    case "--kdf":
                        useKdf = true; break;
                    case "-h":
                    case "--help":
                        System.out.println("Usage: EncryptMessage [--message|-m <text>] [--output|-o <file>] [--show-keys] [--show-private] [--kdf]");
                        return;
                }
            }
            // Ensure RSA keys exist
            if (!Files.exists(Paths.get("recipient_public.der")) || !Files.exists(Paths.get("recipient_private.der"))) {
                System.out.println("Generating RSA key pair...");
                RSAUtil.generateAndSaveKeyPair("recipient_public.der", "recipient_private.der");
                System.out.println("RSA keys generated.");
            }
            // Load keys (optionally print based on flags)
            java.security.PublicKey pub = null;
            java.security.PrivateKey priv = null;
            try {
                pub = RSAUtil.loadPublicKey("recipient_public.der");
                if (showKeys) {
                    byte[] pubBytes = pub.getEncoded();
                    System.out.println("\nRecipient Public Key (PEM):\n" + toPem(pubBytes, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"));
                }
            } catch (Exception e) {
                System.out.println("Warning: failed to load recipient_public.der: " + e.getMessage());
            }
            try {
                priv = RSAUtil.loadPrivateKey("recipient_private.der");
                if (showPrivate) {
                    byte[] privBytes = priv.getEncoded();
                    System.out.println("\nRecipient Private Key (PEM):\n" + toPem(privBytes, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"));
                }
            } catch (Exception e) {
                System.out.println("Warning: failed to load recipient_private.der: " + e.getMessage());
            }

            String message = messageArg != null ? messageArg : System.getenv("MESSAGE");
            if (message == null || message.trim().isEmpty()) {
                message = "This is a test of the location-restricted message system.";
            }

            // Show plaintext (sender view)
            System.out.println("\nPlaintext message:\n" + message + "\n");

            // Generate AES key (either random or derived via KDF)
            SecretKey aesKey;
            if (useKdf) {
                // Derive AES-128 key from message using SHA-256 (first 16 bytes)
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(message.getBytes(StandardCharsets.UTF_8));
                byte[] aesBytes = new byte[16];
                System.arraycopy(hash, 0, aesBytes, 0, 16);
                aesKey = AESUtil.fromBytes(aesBytes);
            } else {
                aesKey = AESUtil.generateAESKey();
            }
            String cipherText = AESUtil.encrypt(message, aesKey);
            
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
            
            // Show encryption details for sender/audit
            System.out.println("\n=== Encryption Details ===");
            // AES key info
            String aesKeyBase64 = java.util.Base64.getEncoder().encodeToString(aesKey.getEncoded());
            System.out.println("AES Key (Base64): " + aesKeyBase64);
            System.out.println("AES Key Algorithm: " + aesKey.getAlgorithm());
            System.out.println("AES Key Length: " + (aesKey.getEncoded().length * 8) + " bits");
            // Cipher text components (IV and ciphertext)
            String[] parts = cipherText.split(":");
            if (parts.length == 2) {
                System.out.println("IV (Base64): " + parts[0]);
                System.out.println("Encrypted Text (Base64): " + parts[1]);
            } else {
                System.out.println("Encrypted output: " + cipherText);
            }
            System.out.println("Encrypted AES Key (Base64): " + encryptedAESKey);
            // Wi-Fi fingerprint (if present)
            if (wifiFP != null && !wifiFP.isEmpty()) {
                System.out.println("Wi-Fi Fingerprint captured (first 10 entries shown):");
                int shown = 0;
                for (Map.Entry<String,Integer> e : wifiFP.entrySet()) {
                    System.out.printf("  %s -> %d%%\n", e.getKey(), e.getValue());
                    if (++shown >= 10) break;
                }
            } else {
                System.out.println("No Wi-Fi fingerprint captured.");
            }

            // Create payload
            String payload = PayloadUtil.createPayload(cipherText, encryptedAESKey, wifiFP);
            Files.write(Paths.get("encrypted_payload.json"), payload.getBytes("UTF-8"));
            System.out.println("\nPayload written to: encrypted_payload.json");
            
        } catch (Exception e) {
            System.err.println("Encryption failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}