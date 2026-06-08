package com.example.networkrestricted;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

public class KDFEncryptDemo {
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

    // Try to load and print recipient RSA keys (PEM) if present
    private static void printRecipientKeysIfPresent() {
        try {
            java.security.PublicKey pub = RSAUtil.loadPublicKey("recipient_public.der");
            System.out.println("\nRecipient Public Key (PEM):\n" + toPem(pub.getEncoded(), "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"));
        } catch (Exception e) {
            System.out.println("(No recipient_public.der available or failed to load: " + e.getMessage() + ")");
        }
        try {
            java.security.PrivateKey priv = RSAUtil.loadPrivateKey("recipient_private.der");
            System.out.println("\nRecipient Private Key (PEM):\n" + toPem(priv.getEncoded(), "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"));
        } catch (Exception e) {
            System.out.println("(No recipient_private.der available or failed to load: " + e.getMessage() + ")");
        }
    }
    // Helper: bytes -> hex
    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    public static void main(String[] args) {
        try {
            // Get user input
            System.out.println("=== Network-Restricted Encryption Demo ===");
            System.out.print("Enter message to encrypt: ");
            String input = new java.util.Scanner(System.in).nextLine();
            if (input == null || input.trim().isEmpty()) {
                System.out.println("No input provided. Using default: 'rohit'");
                input = "rohit";
            }

            System.out.println("\n=== Location Verification (WiFi Fingerprint) ===");
            Map<String,Integer> wifiFingerprint = WifiScanner.getWifiFingerprint();
            if (wifiFingerprint != null && !wifiFingerprint.isEmpty()) {
                System.out.println("Location verified with following WiFi networks:");
                int shown = 0;
                for (Map.Entry<String,Integer> e : wifiFingerprint.entrySet()) {
                    System.out.printf("  BSSID: %s, Signal Strength: %d%%\n", e.getKey(), e.getValue());
                    if (++shown >= 10) break;
                }
            } else {
                System.out.println("Warning: No Wi-Fi networks detected for location verification.");
            }

            System.out.println("\n=== RSA Key Infrastructure ===");
            System.out.println("1. Loading RSA-2048 Key Pair for Secure Key Exchange:");
            printRecipientKeysIfPresent();

            System.out.println("\n=== Input Parameters ===");
            System.out.println("Original message: '" + input + "'");
            System.out.println("Message length: " + input.length() + " bytes");
            System.out.println("Message bytes (UTF-8): " + toHex(input.getBytes(StandardCharsets.UTF_8)));

            System.out.println("\n=== Key Derivation Process ===");
            System.out.println("1. Generating SHA-256 hash of input");
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(input.getBytes(StandardCharsets.UTF_8));
            System.out.println("   Full SHA-256 hash: " + toHex(hash));
            
            System.out.println("2. Extracting first 16 bytes for AES-128 key");
            byte[] aesKey = new byte[16];
            System.arraycopy(hash, 0, aesKey, 0, 16);

            System.out.println("\n=== AES Key Details ===");
            System.out.println("Derived AES-128 Key:");
            System.out.println("  Base64: " + Base64.getEncoder().encodeToString(aesKey));
            System.out.println("  Hex   : " + toHex(aesKey));
            System.out.println("  Length: 128 bits (16 bytes)");

            System.out.println("\n=== Encryption Process ===");
            System.out.println("1. Initialization Vector (IV)");
            byte[] iv = new byte[16]; // zeros by default
            System.out.println("   Using demo IV (all zeros - NOT for production)");
            System.out.println("   IV Base64: " + Base64.getEncoder().encodeToString(iv));
            System.out.println("   IV Hex   : " + toHex(iv));

            System.out.println("\n2. Setting up AES Cipher");
            System.out.println("   Mode: CBC (Cipher Block Chaining)");
            System.out.println("   Padding: PKCS#7");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            System.out.println("\n3. PKCS#7 Padding Process");
            byte[] plainBytes = input.getBytes(StandardCharsets.UTF_8);
            int blockSize = 16;
            int padLen = blockSize - (plainBytes.length % blockSize);
            if (padLen == 0) padLen = blockSize;
            byte[] padded = new byte[plainBytes.length + padLen];
            System.arraycopy(plainBytes, 0, padded, 0, plainBytes.length);
            for (int i = plainBytes.length; i < padded.length; i++) padded[i] = (byte) padLen;

            System.out.println("   Block size: " + blockSize + " bytes");
            System.out.println("   Original length: " + plainBytes.length + " bytes");
            System.out.println("   Padding needed: " + padLen + " bytes");
            System.out.println("   Padding value: 0x" + String.format("%02x", padLen) + " (repeated " + padLen + " times)");
            System.out.println("   Final length: " + padded.length + " bytes");
            System.out.println("   Padded data (hex): " + toHex(padded));
            System.out.println("   Padded data (Base64): " + Base64.getEncoder().encodeToString(padded));

            System.out.println("\n4. AES Encryption");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] ciphertext = cipher.doFinal(padded);

            System.out.println("   Final ciphertext:");
            System.out.println("   Base64: " + Base64.getEncoder().encodeToString(ciphertext));
            System.out.println("   Hex: " + toHex(ciphertext));

            System.out.println("\n5. Block-by-Block View:");
            for (int i = 0; i < ciphertext.length; i += blockSize) {
                int end = Math.min(i + blockSize, ciphertext.length);
                byte[] blk = new byte[end - i];
                System.arraycopy(ciphertext, i, blk, 0, blk.length);
                System.out.printf("   Block %d (bytes %2d-%2d): %s%n", 
                    i/blockSize, i, end-1, toHex(blk));
            }

            // Step 4b: Decrypt to verify (manual unpadding)
            Cipher dec = Cipher.getInstance("AES/CBC/NoPadding");
            dec.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decryptedPadded = dec.doFinal(ciphertext);
            System.out.println("\nDecrypted padded (hex): " + toHex(decryptedPadded));
            // remove PKCS#7 padding
            int padByte = decryptedPadded[decryptedPadded.length - 1] & 0xff;
            if (padByte < 1 || padByte > blockSize) {
                System.out.println("Invalid padding value: " + padByte);
            }
            int plainLen = decryptedPadded.length - padByte;
            byte[] recovered = new byte[plainLen];
            System.arraycopy(decryptedPadded, 0, recovered, 0, plainLen);
            String plaintext = new String(recovered, StandardCharsets.UTF_8);
            System.out.println("Unpadded plaintext: '" + plaintext + "'");

        } catch (Exception e) {
            System.err.println("Demo failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
